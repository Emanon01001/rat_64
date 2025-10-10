use crate::config::AUTH_TOKEN;
use crate::state::{log_activity, AppState};
use crate::types::Command;
use crate::util::{
    bytes_download_response, extract_json_body, json_response, parse_query_param, unix_time,
};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::{body::Incoming, Request, Response, StatusCode};
use serde_json::{json, Value};
use std::convert::Infallible;

pub async fn handle_simple_command(
    state: &AppState,
    prefix: &str,
    command_type: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let id = format!("{}_{}", prefix, Utc::now().timestamp_millis());
    let cmd = Command {
        id: id.clone(),
        command_type: command_type.to_string(),
        parameters: vec![],
        timestamp: unix_time(),
        auth_token: AUTH_TOKEN.to_string(),
    };

    state.command_queue.lock().await.push(cmd);
    state.notify.notify_waiters();

    log_activity(
        state,
        "INFO",
        &format!("{} command queued", command_type),
        None,
        Some(&id),
        Some(json!({"command_type": command_type})),
    )
    .await;

    Ok(json_response(json!({"ok": true}), StatusCode::OK))
}

pub async fn handle_file_command(
    state: &AppState,
    prefix: &str,
    command_type: &str,
    params: Vec<&str>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let id = format!("{}_{}", prefix, Utc::now().timestamp_millis());
    let cmd = Command {
        id: id.clone(),
        command_type: command_type.to_string(),
        parameters: params.into_iter().map(String::from).collect(),
        timestamp: unix_time(),
        auth_token: AUTH_TOKEN.to_string(),
    };

    state.command_queue.lock().await.push(cmd);
    state.notify.notify_waiters();

    Ok(json_response(json!({"ok": true}), StatusCode::OK))
}

pub async fn handle_file_operation(
    state: &AppState,
    req: Request<Incoming>,
    operation: &str,
    command_type: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match extract_json_body(req).await {
        Ok(data) => {
            if let Some(path) = data.get("path").and_then(|p| p.as_str()) {
                let id = format!("{}_{}", operation, Utc::now().timestamp_millis());
                let params = match operation {
                    "delete" => vec![path.to_string(), "false".to_string()],
                    "create_dir" => vec![path.to_string(), "true".to_string()],
                    "download" => vec![path.to_string(), "52428800".to_string()],
                    _ => vec![path.to_string()],
                };

                let cmd = Command {
                    id: id.clone(),
                    command_type: command_type.to_string(),
                    parameters: params,
                    timestamp: unix_time(),
                    auth_token: AUTH_TOKEN.to_string(),
                };

                state.command_queue.lock().await.push(cmd);
                state.notify.notify_waiters();

                Ok(json_response(
                    json!({"ok": true, "command_id": id}),
                    StatusCode::OK,
                ))
            } else {
                Ok(json_response(
                    json!({"error": "path parameter required"}),
                    StatusCode::BAD_REQUEST,
                ))
            }
        }
        Err(_) => Ok(json_response(
            json!({"error": "Invalid JSON"}),
            StatusCode::BAD_REQUEST,
        )),
    }
}

pub async fn handle_command(
    state: &AppState,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match extract_json_body(req).await {
        Ok(data) => {
            if let Some(command) = data.get("command").and_then(|c| c.as_str()) {
                let timeout = data.get("timeout").and_then(|t| t.as_u64()).unwrap_or(30);
                let working_dir = data
                    .get("working_dir")
                    .and_then(|w| w.as_str())
                    .unwrap_or("");

                let id = format!("cmd{}", Utc::now().timestamp_millis());
                let params = vec![
                    command.to_string(),
                    timeout.to_string(),
                    working_dir.to_string(),
                ];

                let command_type = "execute";
                let cmd = Command {
                    id: id.clone(),
                    command_type: command_type.to_string(),
                    parameters: params,
                    timestamp: unix_time(),
                    auth_token: AUTH_TOKEN.to_string(),
                };

                state.command_queue.lock().await.push(cmd);
                state.notify.notify_waiters();

                log_activity(
                    state,
                    "INFO",
                    &format!("command queued: {}", command),
                    None,
                    Some(&id),
                    Some(json!({
                        "command": command,
                        "timeout": timeout,
                        "working_dir": working_dir
                    })),
                )
                .await;

                Ok(json_response(
                    json!({"ok": true, "command_id": id}),
                    StatusCode::OK,
                ))
            } else {
                Ok(json_response(
                    json!({"error": "command parameter required"}),
                    StatusCode::BAD_REQUEST,
                ))
            }
        }
        Err(_) => Ok(json_response(
            json!({"error": "Invalid JSON"}),
            StatusCode::BAD_REQUEST,
        )),
    }
}

pub async fn ui_download_response_file(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let Some(cmd_id) = parse_query_param(&req, "command_id") else {
        return Ok(json_response(
            json!({"error":"command_id required"}),
            StatusCode::BAD_REQUEST,
        ));
    };

    let logs = state.response_log.lock().await;
    if let Some(item) = logs
        .iter()
        .rev()
        .find(|v| v.get("command_id").and_then(|s| s.as_str()) == Some(cmd_id.as_str()))
    {
        if let Some(data) = item.get("data") {
            let file_name = data
                .get("file_name")
                .and_then(|s| s.as_str())
                .unwrap_or("download.bin");
            let encoding = data.get("encoding").and_then(|s| s.as_str()).unwrap_or("");
            let b64 = data.get("data").and_then(|s| s.as_str());
            if encoding == "base64" {
                if let Some(b64s) = b64 {
                    match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64s) {
                        Ok(bytes) => return Ok(bytes_download_response(file_name, bytes)),
                        Err(_) => {
                            return Ok(json_response(
                                json!({"error":"Failed to decode base64"}),
                                StatusCode::BAD_REQUEST,
                            ))
                        }
                    }
                }
            }
        }
    }

    Ok(json_response(
        json!({"error":"file not found or not base64"}),
        StatusCode::NOT_FOUND,
    ))
}

pub async fn ui_state_json(state: &AppState) -> Result<Response<Full<Bytes>>, Infallible> {
    let q = state.command_queue.lock().await;
    let r = state.response_log.lock().await;
    let recent: Vec<Value> = r.iter().rev().take(20).cloned().collect();
    Ok(json_response(
        json!({
            "queue_count": q.len(),
            "responses": recent
        }),
        StatusCode::OK,
    ))
}
