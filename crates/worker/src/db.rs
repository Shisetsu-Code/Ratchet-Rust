use crate::http::ApiResult;
use serde::de::DeserializeOwned;
use serde_json::Value;
use worker::{D1Database, D1PreparedStatement, D1Result, wasm_bindgen::JsValue};

pub struct Db(pub D1Database);
impl Db {
    pub fn statement(&self, sql: &str, values: &[Value]) -> ApiResult<D1PreparedStatement> {
        let bindings: Vec<JsValue> = values
            .iter()
            .map(|value| match value {
                Value::Null => JsValue::NULL,
                Value::Bool(b) => JsValue::from_f64(if *b { 1.0 } else { 0.0 }),
                Value::Number(n) => JsValue::from_f64(n.as_f64().unwrap_or_default()),
                Value::String(s) => JsValue::from_str(s),
                _ => JsValue::from_str(&value.to_string()),
            })
            .collect();
        Ok(self.0.prepare(sql).bind(&bindings)?)
    }
    pub async fn first<T: DeserializeOwned>(
        &self,
        sql: &str,
        values: &[Value],
    ) -> ApiResult<Option<T>> {
        Ok(self.statement(sql, values)?.first(None).await?)
    }
    pub async fn all(&self, sql: &str, values: &[Value]) -> ApiResult<Vec<Value>> {
        Ok(self.statement(sql, values)?.all().await?.results()?)
    }
    pub async fn run(&self, sql: &str, values: &[Value]) -> ApiResult<D1Result> {
        Ok(self.statement(sql, values)?.run().await?)
    }
}
