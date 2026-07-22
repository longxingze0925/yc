use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::ApiResult;
use crate::{AppState, RequestId};

use super::authenticate;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    limit: Option<usize>,
    before_epoch_millis: Option<u64>,
}

pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let before = query.before_epoch_millis.unwrap_or(u64::MAX);
    let mut entries = Vec::new();
    state
        .repository
        .read(&mut |database| {
            entries = database
                .audit_logs
                .iter()
                .rev()
                .filter(|entry| {
                    entry.actor_account_id.as_deref() == Some(&claims.account_id)
                        && entry.created_at_epoch_millis < before
                })
                .take(limit)
                .cloned()
                .collect();
        })
        .await;
    Ok(Json(json!({ "audit_logs": entries })))
}
