use axum::extract::State as AxState;
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::service::Vault;
use crate::state::Rule;

pub type Shared = Arc<Mutex<Vault>>;

const INDEX_HTML: &str = include_str!("../static/index.html");

pub fn router(shared: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(get_state))
        .route("/api/rules", post(add_rule))
        .route("/api/preview", post(preview))
        .route("/api/redact", post(redact))
        .route("/api/restore", post(restore))
        .route("/api/rotate", post(rotate))
        .route("/api/audit/verify", get(verify_audit))
        .route("/api/export", get(export))
        .with_state(shared)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

fn err(status: StatusCode, msg: String) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"error": msg})))
}

async fn get_state(AxState(s): AxState<Shared>) -> Json<Value> {
    let v = s.lock().unwrap();
    let st = &v.store.state;
    Json(json!({
        "rules": st.rules,
        "current_gen": st.current_gen,
        "generations": v.store.keys.generations.iter().map(|g| g.id).collect::<Vec<_>>(),
        "mapping_count": st.mappings.len(),
        "audit": st.audit,
        "redactions": st.redactions,
    }))
}

async fn add_rule(
    AxState(s): AxState<Shared>,
    Json(rule): Json<Rule>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut v = s.lock().unwrap();
    v.register_rule(rule).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Deserialize)]
struct TextReq {
    text: String,
}

async fn preview(
    AxState(s): AxState<Shared>,
    Json(req): Json<TextReq>,
) -> Json<Value> {
    let v = s.lock().unwrap();
    Json(json!(v.preview(&req.text)))
}

#[derive(Deserialize)]
struct RedactReq {
    tenant: String,
    text: String,
}

async fn redact(
    AxState(s): AxState<Shared>,
    Json(req): Json<RedactReq>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut v = s.lock().unwrap();
    let outcome = v.redact(&req.tenant, &req.text).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!(outcome)))
}

#[derive(Deserialize)]
struct RestoreReq {
    purpose: String,
    tokens: Vec<String>,
}

async fn restore(
    AxState(s): AxState<Shared>,
    Json(req): Json<RestoreReq>,
) -> Json<Value> {
    let mut v = s.lock().unwrap();
    Json(json!({"results": v.restore(&req.purpose, &req.tokens)}))
}

async fn rotate(AxState(s): AxState<Shared>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut v = s.lock().unwrap();
    let gen = v.rotate().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({"ok": true, "current_gen": gen})))
}

async fn verify_audit(AxState(s): AxState<Shared>) -> Json<Value> {
    let v = s.lock().unwrap();
    Json(json!({
        "ok": v.verify_audit(),
        "length": v.store.state.audit.len(),
        "head": v.store.state.audit.last().map(|a| a.hash.clone()),
    }))
}

async fn export(AxState(s): AxState<Shared>) -> Json<Value> {
    let v = s.lock().unwrap();
    Json(json!(v.export()))
}
