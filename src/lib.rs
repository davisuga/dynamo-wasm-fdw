#[allow(warnings)]
mod bindings;
use serde_json::{Value as JsonValue, json};
use std::collections::HashMap;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use base16::encode_lower;
use chrono::Utc;
use serde::{Serialize, Deserialize};

use bindings::{
    exports::supabase::wrappers::routines::Guest,
    supabase::wrappers::{
        http, stats,
        types::{Cell, Context, FdwError, FdwResult, OptionsType, Row, TypeOid},
        utils,
    },
};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct AttributeValue {
    value_type: AttributeValueType,
    value: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
enum AttributeValueType {
    #[default]
    Null,
    String,
    Number,
    Boolean,
    List,
    Map,
}

impl AttributeValue {
    fn s(value: String) -> Self {
        Self {
            value_type: AttributeValueType::String,
            value,
        }
    }

    fn n(value: String) -> Self {
        Self {
            value_type: AttributeValueType::Number,
            value,
        }
    }

    fn bool(value: bool) -> Self {
        Self {
            value_type: AttributeValueType::Boolean,
            value: value.to_string(),
        }
    }

    fn null() -> Self {
        Self {
            value_type: AttributeValueType::Null,
            value: String::new(),
        }
    }

    fn list(values: Vec<AttributeValue>) -> Self {
        Self {
            value_type: AttributeValueType::List,
            value: serde_json::to_string(&values).unwrap_or_default(),
        }
    }

    fn map(values: HashMap<String, AttributeValue>) -> Self {
        Self {
            value_type: AttributeValueType::Map,
            value: serde_json::to_string(&values).unwrap_or_default(),
        }
    }
}

#[derive(Debug, Default)]
struct DynamoFdw {
    base_url: String,
    headers: Vec<(String, String)>,
    table_name: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    src_rows: Vec<JsonValue>,
    src_idx: usize,
    where_conditions: Vec<(String, String, String)>, // (column, operator, value)
    limit: Option<i32>,
    order_by: Option<(String, bool)>, // (column, is_ascending)
}

static mut INSTANCE: *mut DynamoFdw = std::ptr::null_mut::<DynamoFdw>();
static FDW_NAME: &str = "DynamoFdw";

impl DynamoFdw {
    fn init_instance() {
        let instance = Self::default();
        unsafe {
            INSTANCE = Box::leak(Box::new(instance));
        }
    }

    fn this_mut() -> &'static mut Self {
        unsafe { &mut (*INSTANCE) }
    }

    fn make_request(
        &self,
        method: http::Method,
        operation: &str,
        body: &str,
    ) -> Result<(http::Response, JsonValue), FdwError> {
        // Generate AWS v4 signature
        let timestamp = current_timestamp();
        let date = &timestamp[0..8];
        
        let method_str = match method {
            http::Method::Get => "GET",
            http::Method::Post => "POST",
            http::Method::Put => "PUT",
            http::Method::Delete => "DELETE",
            http::Method::Patch => "PATCH",
        };

        let canonical_request = format!(
            "{}\n/{}\n\n{}",
            method_str,
            operation,
            body
        );

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}/{}/dynamodb/aws4_request\n{}",
            timestamp,
            date,
            self.region,
            sha256_hex(&canonical_request)
        );

        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_access_key).as_bytes(),
            date.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"dynamodb");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hmac_sha256_hex(&k_signing, string_to_sign.as_bytes());

        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}/{}/dynamodb/aws4_request, SignedHeaders=host;x-amz-date, Signature={}",
            self.access_key_id,
            date,
            self.region,
            signature
        );

        let mut headers = vec![
            ("Authorization".to_string(), auth_header),
            ("X-Amz-Date".to_string(), timestamp),
            ("Content-Type".to_string(), "application/x-amz-json-1.0".to_string()),
            ("X-Amz-Target".to_string(), format!("DynamoDB_20120810.{}", operation)),
        ];
        headers.extend(self.headers.clone());

        let req = http::Request {
            method,
            url: self.base_url.clone(),
            headers,
            body: body.to_owned(),
        };

        let resp = match method {
            http::Method::Get => http::get(&req),
            http::Method::Post => http::post(&req),
            _ => unreachable!(),
        }?;

        let json_value = serde_json::from_str(&resp.body).map_err(|e| e.to_string())?;

        stats::inc_stats(FDW_NAME, stats::Metric::BytesIn, resp.body.len() as i64);
        stats::inc_stats(FDW_NAME, stats::Metric::BytesOut, body.len() as i64);

        Ok((resp, json_value))
    }

    fn query_table(&mut self) -> FdwResult {
        let mut query_body = json!({
            "TableName": self.table_name,
            "Select": "ALL_ATTRIBUTES"
        });

        // Add key conditions if any
        if !self.where_conditions.is_empty() {
            let (key_condition, values) = self.build_key_condition();
            query_body["KeyConditionExpression"] = JsonValue::String(key_condition);
            query_body["ExpressionAttributeValues"] = JsonValue::Object(
                values.into_iter()
                    .map(|(k, v)| (k, attribute_to_json(v)))
                    .collect()
            );
        }

        // Add limit if specified
        if let Some(limit) = self.limit {
            query_body["Limit"] = JsonValue::Number(serde_json::Number::from(limit));
        }

        let (resp, resp_json) = self.make_request(
            http::Method::Post,
            "Query",
            &serde_json::to_string(&query_body).unwrap(),
        )?;

        http::error_for_status(&resp)?;

        // Extract items from response
        self.src_rows = resp_json
            .as_object()
            .and_then(|v| v.get("Items"))
            .and_then(|v| v.as_array())
            .map(|v| v.to_owned())
            .ok_or("cannot get items from response")?;

        // Apply ordering if specified
        if let Some((column, is_ascending)) = &self.order_by {
            self.src_rows.sort_by(|a, b| {
                let a_val = a.get(column);
                let b_val = b.get(column);
                if *is_ascending {
                    match (a_val, b_val) {
                        (Some(a), Some(b)) => match (a.as_str(), b.as_str()) {
                            (Some(a_str), Some(b_str)) => a_str.cmp(b_str),
                            _ => std::cmp::Ordering::Equal,
                        },
                        (None, Some(_)) => std::cmp::Ordering::Less,
                        (Some(_), None) => std::cmp::Ordering::Greater,
                        (None, None) => std::cmp::Ordering::Equal,
                    }
                } else {
                    match (a_val, b_val) {
                        (Some(a), Some(b)) => match (a.as_str(), b.as_str()) {
                            (Some(a_str), Some(b_str)) => b_str.cmp(a_str),
                            _ => std::cmp::Ordering::Equal,
                        },
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, None) => std::cmp::Ordering::Equal,
                    }
                }
            });
        }

        stats::inc_stats(FDW_NAME, stats::Metric::RowsIn, self.src_rows.len() as i64);
        stats::inc_stats(FDW_NAME, stats::Metric::RowsOut, self.src_rows.len() as i64);

        Ok(())
    }
}

impl Guest for DynamoFdw {
    fn host_version_requirement() -> String {
        "^0.1.0".to_string()
    }

    fn init(ctx: &Context) -> FdwResult {
        let opts = ctx.get_options(OptionsType::Server);
        
        Self::init_instance();
        let this = Self::this_mut();

        this.region = opts.require_or("region", "us-east-1");
        this.base_url = format!("https://dynamodb.{}.amazonaws.com", this.region);
        
        // Get AWS credentials
        this.access_key_id = match opts.get("access_key_id") {
            Some(key) => key,
            None => {
                let key_id = opts.require("access_key_id_secret")?;
                utils::get_vault_secret(&key_id).unwrap_or_default()
            }
        };

        this.secret_access_key = match opts.get("secret_access_key") {
            Some(key) => key,
            None => {
                let key_id = opts.require("secret_access_key_secret")?;
                utils::get_vault_secret(&key_id).unwrap_or_default()
            }
        };

        // Set common headers
        this.headers.push(("User-Agent".to_string(), "Wrappers DynamoDB FDW".to_string()));
        this.headers.push(("Host".to_string(), format!("dynamodb.{}.amazonaws.com", this.region)));

        stats::inc_stats(FDW_NAME, stats::Metric::CreateTimes, 1);

        Ok(())
    }

    fn begin_scan(ctx: &Context) -> FdwResult {
        let this = Self::this_mut();
        let opts = ctx.get_options(OptionsType::Table);
        this.table_name = opts.require("table_name")?;

        // Parse where conditions if any
        if let Some(where_clause) = opts.get("where") {
            this.where_conditions = where_clause
                .split(',')
                .filter_map(|condition| {
                    let parts: Vec<&str> = condition.split(':').collect();
                    if parts.len() == 3 {
                        Some((
                            parts[0].to_string(),
                            parts[1].to_string(),
                            parts[2].to_string(),
                        ))
                    } else {
                        None
                    }
                })
                .collect();
        }

        // Parse limit if any
        if let Some(limit_str) = opts.get("limit") {
            this.limit = limit_str.parse::<i32>().ok();
        }

        // Parse order by if any
        if let Some(order_by) = opts.get("order_by") {
            let parts: Vec<&str> = order_by.split(':').collect();
            if parts.len() == 2 {
                this.order_by = Some((
                    parts[0].to_string(),
                    parts[1].to_lowercase() == "asc",
                ));
            }
        }

        this.query_table()
    }

    fn iter_scan(ctx: &Context, row: &Row) -> Result<Option<u32>, FdwError> {
        let this = Self::this_mut();

        if this.src_idx >= this.src_rows.len() {
            return Ok(None);
        }

        let src_row = &this.src_rows[this.src_idx];
        for tgt_col in ctx.get_columns() {
            let tgt_col_name = tgt_col.name();
            let src = src_row
                .as_object()
                .and_then(|v| v.get(&tgt_col_name))
                .ok_or(format!("source column '{}' not found", tgt_col_name))?;
            
            let cell = match tgt_col.type_oid() {
                TypeOid::Bool => src.as_bool().map(Cell::Bool),
                TypeOid::String => src.as_str().map(|v| Cell::String(v.to_owned())),
                TypeOid::I64 => src.as_f64().map(|v| Cell::I64(v as i64)),
                TypeOid::Json => Some(Cell::Json(src.to_string())),
                _ => {
                    return Err(format!(
                        "column {} data type is not supported",
                        tgt_col_name
                    ));
                }
            };

            row.push(cell.as_ref());
        }

        this.src_idx += 1;
        Ok(Some(0))
    }

    fn end_scan(_ctx: &Context) -> FdwResult {
        let this = Self::this_mut();
        this.src_rows.clear();
        this.src_idx = 0;
        this.where_conditions.clear();
        this.limit = None;
        this.order_by = None;
        Ok(())
    }

    fn re_scan(_ctx: &Context) -> FdwResult {
        Err("re_scan on foreign table is not supported".to_owned())
    }

    fn begin_modify(_ctx: &Context) -> FdwResult {
        Err("modify on foreign table is not supported".to_owned())
    }

    fn insert(_ctx: &Context, _row: &Row) -> FdwResult {
        Err("insert on foreign table is not supported".to_owned())
    }

    fn update(_ctx: &Context, _rowid: Cell, _row: &Row) -> FdwResult {
        Err("update on foreign table is not supported".to_owned())
    }

    fn delete(_ctx: &Context, _rowid: Cell) -> FdwResult {
        Err("delete on foreign table is not supported".to_owned())
    }

    fn end_modify(_ctx: &Context) -> FdwResult {
        Ok(())
    }
}

// Helper function to convert DynamoDB AttributeValue to JSON Value
fn attribute_to_json(attr: AttributeValue) -> JsonValue {
    match attr.value_type {
        AttributeValueType::String => JsonValue::String(attr.value),
        AttributeValueType::Number => {
            if let Ok(num) = attr.value.parse::<f64>() {
                if let Some(num_val) = serde_json::Number::from_f64(num) {
                    JsonValue::Number(num_val)
                } else {
                    JsonValue::Null
                }
            } else {
                JsonValue::Null
            }
        }
        AttributeValueType::Boolean => {
            if let Ok(b) = attr.value.parse::<bool>() {
                JsonValue::Bool(b)
            } else {
                JsonValue::Null
            }
        }
        AttributeValueType::List => {
            if let Ok(list) = serde_json::from_str::<Vec<AttributeValue>>(&attr.value) {
                JsonValue::Array(list.into_iter().map(attribute_to_json).collect())
            } else {
                JsonValue::Null
            }
        }
        AttributeValueType::Map => {
            if let Ok(map) = serde_json::from_str::<HashMap<String, AttributeValue>>(&attr.value) {
                JsonValue::Object(
                    map.into_iter()
                        .map(|(k, v)| (k, attribute_to_json(v)))
                        .collect()
                )
            } else {
                JsonValue::Null
            }
        }
        AttributeValueType::Null => JsonValue::Null,
    }
}

impl DynamoFdw {
    fn build_key_condition(&self) -> (String, std::collections::HashMap<String, AttributeValue>) {
        let mut condition = String::new();
        let mut values = std::collections::HashMap::new();
        
        for (i, (column, operator, value)) in self.where_conditions.iter().enumerate() {
            if i > 0 {
                condition.push_str(" AND ");
            }
            
            let placeholder = format!(":val{}", i);
            match operator.as_str() {
                "=" => condition.push_str(&format!("{} = {}", column, placeholder)),
                ">" => condition.push_str(&format!("{} > {}", column, placeholder)),
                "<" => condition.push_str(&format!("{} < {}", column, placeholder)),
                ">=" => condition.push_str(&format!("{} >= {}", column, placeholder)),
                "<=" => condition.push_str(&format!("{} <= {}", column, placeholder)),
                "begins_with" => condition.push_str(&format!("begins_with({}, {})", column, placeholder)),
                _ => continue,
            }
            
            values.insert(
                placeholder,
                AttributeValue::s(value.clone()),
            );
        }
        
        (condition, values)
    }
}

bindings::export!(DynamoFdw with_types_in bindings);

// Helper functions for AWS signing
fn current_timestamp() -> String {
    Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    encode_lower(&hasher.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    encode_lower(&hmac_sha256(key, data))
}
