use crate::config::AUTH_TOKEN;
use crate::state::{log_activity, AppState};
use crate::types::{ClientInfo, Command, DriveInfo, LogEntry};
use crate::util::{
    extract_json_body, is_authorized, json_response, log_request, parse_query_bool,
    parse_query_param, parse_query_u64, unauthorized, unix_time,
};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::{body::Incoming, Request, Response, StatusCode};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time;

async fn handle_client_json_request<F>(
    state: &AppState,
    req: Request<Incoming>,
    processor: F,
    response_status: &str,
) -> Result<Response<Full<Bytes>>, Infallible>
where
    F: FnOnce(Value) -> Value,
{
    match extract_json_body(req).await {
        Ok(data) => {
            let processed_data = processor(data);

            if response_status != "received" {
                state.response_log.lock().await.push(processed_data);
            } else {
                state
                    .response_log
                    .lock()
                    .await
                    .push(processed_data.clone());
            }

            Ok(json_response(
                json!({"status": response_status}),
                StatusCode::OK,
            ))
        }
        Err(_) => Ok(json_response(
            json!({"error": "No JSON data provided"}),
            StatusCode::BAD_REQUEST,
        )),
    }
}

pub async fn api_commands_fetch(
    req: Request<Incoming>,
    remote: SocketAddr,
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    log_request(req.method(), req.uri().path(), &remote, None);
    if !is_authorized(&req) {
        return Ok(unauthorized());
    }
    let client_id = parse_query_param(&req, "client_id").unwrap_or_else(|| "unknown".into());
    let wait = parse_query_bool(&req, "wait");
    let timeout_secs = parse_query_u64(&req, "timeout", 25);

    let mut cmds: Vec<Command> = {
        let q = state.command_queue.lock().await;
        q.clone()
    };
    if cmds.is_empty() && wait {
        let _ = time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            state.notify.notified(),
        )
        .await;
        let q = state.command_queue.lock().await;
        cmds = q.clone();
    }

    if !cmds.is_empty() {
        let mut q = state.command_queue.lock().await;
        let current_time = unix_time();
        q.retain(|cmd| current_time - cmd.timestamp < 5);
    }
    if !cmds.is_empty() {
        println!(
            "  → Returning {} command(s) for client: {}",
            cmds.len(), client_id
        );
    }
    Ok(json_response(
        serde_json::to_value(cmds).unwrap_or_else(|_| json!([])),
        StatusCode::OK,
    ))
}

pub async fn api_commands_response(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if !is_authorized(&req) {
        return Ok(unauthorized());
    }
    match extract_json_body(req).await {
        Ok(mut data) => {
            let command_id = data
                .get("command_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let success = data
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let message = data
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("no message");
            println!(
                "  → Command response received: {} (success: {}) - {}",
                command_id, success, message
            );

            if let Some(obj) = data.as_object_mut() {
                obj.insert("received_at".into(), Value::String(Utc::now().to_rfc3339()));
                obj.insert("server_timestamp".into(), Value::from(unix_time()));
            }
            state.response_log.lock().await.push(data.clone());

            if let (Some(client_id), Some(resp_data)) = (
                data.get("client_id").and_then(|v| v.as_str()),
                data.get("data"),
            ) {
                if let Some(sys) = resp_data.as_object() {
                    if sys.get("hostname").is_some() && sys.get("os_name").is_some() {
                        let mut clients = state.client_info.lock().await;
                        let drives = sys
                            .get("disk_info")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|drive| {
                                        Some(DriveInfo {
                                            drive_letter: drive
                                                .get("drive_letter")?
                                                .as_str()?
                                                .to_string(),
                                            drive_type: "Fixed".to_string(),
                                            total_space_gb: drive.get("total_size_gb")?.as_f64()?,
                                            free_space_gb: drive.get("free_space_gb")?.as_f64()?,
                                            file_system: drive
                                                .get("file_system")?
                                                .as_str()?
                                                .to_string(),
                                        })
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();

                        let client_info = ClientInfo {
                            client_id: client_id.to_string(),
                            hostname: sys
                                .get("hostname")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            username: sys
                                .get("username")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            os_name: sys
                                .get("os_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            os_version: sys
                                .get("os_version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            architecture: sys
                                .get("os_arch")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            cpu_info: sys
                                .get("cpu_info")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            timezone: sys
                                .get("timezone")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            is_virtual_machine: sys
                                .get("is_virtual_machine")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            virtual_machine_vendor: sys
                                .get("virtual_machine_vendor")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            drives,
                            last_seen: unix_time(),
                            status: "updated".to_string(),
                            public_ip: sys
                                .get("public_ip")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                        };
                        clients.insert(client_id.to_string(), client_info);
                    }
                }
            }

            Ok(json_response(json!({"status":"received"}), StatusCode::OK))
        }
        Err(_) => Ok(json_response(
            json!({"error": "No JSON data provided"}),
            StatusCode::BAD_REQUEST,
        )),
    }
}

pub async fn api_heartbeat(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if !is_authorized(&req) {
        return Ok(unauthorized());
    }
    handle_client_json_request(
        &state,
        req,
        |data| {
            let client_id = data
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let hostname = data
                .get("hostname")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let status = data
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            tokio::spawn({
                let state = Arc::clone(&state);
                let data = data.clone();
                let client_id = client_id.to_string();
                let hostname = hostname.to_string();
                let status = status.to_string();
                async move {
                    println!(
                        "🔍 Heartbeat received from {}: {}",
                        client_id,
                        serde_json::to_string_pretty(&data)
                            .unwrap_or_else(|_| "invalid json".to_string())
                    );

                    let mut clients = state.client_info.lock().await;

                    if let Some(system_info) = data.get("system_info").and_then(|v| {
                        if v.is_null() { None } else { Some(v) }
                    }) {
                        println!("✅ System info found in heartbeat from {}", client_id);
                        let client_info = ClientInfo {
                            client_id: client_id.clone(),
                            hostname: hostname.clone(),
                            username: system_info
                                .get("username")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            os_name: system_info
                                .get("os_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            os_version: system_info
                                .get("os_version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            architecture: system_info
                                .get("os_arch")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            cpu_info: system_info
                                .get("cpu_info")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            timezone: system_info
                                .get("timezone")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            is_virtual_machine: system_info
                                .get("is_virtual_machine")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            virtual_machine_vendor: system_info
                                .get("virtual_machine_vendor")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            drives: system_info
                                .get("disk_info")
                                .and_then(|v| v.as_array())
                                .map(|drives| {
                                    drives
                                        .iter()
                                        .filter_map(|drive| {
                                            Some(DriveInfo {
                                                drive_letter: drive
                                                    .get("drive_letter")?
                                                    .as_str()?
                                                    .to_string(),
                                                drive_type: "Fixed".to_string(),
                                                total_space_gb: drive
                                                    .get("total_size_gb")?
                                                    .as_f64()?,
                                                free_space_gb: drive
                                                    .get("free_space_gb")?
                                                    .as_f64()?,
                                                file_system: drive
                                                    .get("file_system")?
                                                    .as_str()?
                                                    .to_string(),
                                            })
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                            last_seen: unix_time(),
                            status: status.clone(),
                            public_ip: system_info
                                .get("public_ip")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                        };
                        clients.insert(client_id.clone(), client_info);
                    } else {
                        let entry = LogEntry {
                            timestamp: unix_time(),
                            level: "HEARTBEAT".to_string(),
                            message: format!(
                                "Heartbeat from {}@{}: {} (no system info)",
                                client_id, hostname, status
                            ),
                            client_id: Some(client_id.clone()),
                            command_id: None,
                            details: None,
                        };
                        state.activity_log.lock().await.push(entry);
                    }

                    log_activity(
                        &state,
                        "HEARTBEAT",
                        &format!("Heartbeat from {}@{}: {}", client_id, hostname, status),
                        Some(&client_id),
                        None,
                        Some(data),
                    )
                    .await;
                }
            });

            println!("  → Heartbeat from {}@{}: {}", client_id, hostname, status);
            data
        },
        "received",
    )
    .await
}

pub async fn api_data_upload(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if !is_authorized(&req) {
        return Ok(unauthorized());
    }
    handle_client_json_request(
        state,
        req,
        |data| {
            let client_id = data
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let data_type = data
                .get("data_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!(
                "  → Data upload received from {}: {} (not saved)",
                client_id, data_type
            );
            data
        },
        "uploaded",
    )
    .await
}

pub async fn api_clients(state: &AppState) -> Result<Response<Full<Bytes>>, Infallible> {
    let clients = state.client_info.lock().await;
    let client_list: Vec<&ClientInfo> = clients.values().collect();
    Ok(json_response(json!({"clients": client_list}), StatusCode::OK))
}

pub async fn api_status(state: &AppState) -> Result<Response<Full<Bytes>>, Infallible> {
    let q = state.command_queue.lock().await;
    let r = state.response_log.lock().await;
    let l = state.activity_log.lock().await;
    let status = serde_json::json!({
        "queue": q.len(),
        "responses": r.len(),
        "logs": l.len(),
        "clients": if r.len() > 0 { 1 } else { 0 },
        "server_time": unix_time(),
        "uptime": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    Ok(json_response(status, StatusCode::OK))
}

pub async fn api_logs(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let limit = parse_query_u64(&req, "limit", 50);
    let offset = parse_query_u64(&req, "offset", 0);

    let logs = state.activity_log.lock().await;
    let total = logs.len();
    let start = offset.min(total as u64) as usize;
    let end = (start + limit as usize).min(total);

    let logs_slice: Vec<LogEntry> = if start < total {
        logs[start..end].iter().rev().cloned().collect()
    } else {
        Vec::new()
    };

    let response = serde_json::json!({
        "logs": logs_slice,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": end < total
    });

    Ok(json_response(response, StatusCode::OK))
}

pub async fn api_logs_clear(state: &AppState) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut logs = state.activity_log.lock().await;
    let cleared_count = logs.len();
    logs.clear();
    log_activity(
        state,
        "INFO",
        &format!("Activity log cleared ({} entries)", cleared_count),
        None,
        None,
        None,
    )
    .await;
    Ok(json_response(
        json!({"cleared": cleared_count, "status": "success"}),
        StatusCode::OK,
    ))
}

pub async fn api_responses(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let limit = parse_query_u64(&req, "limit", 10);
    let command_id = parse_query_param(&req, "command_id");

    let responses = state.response_log.lock().await;
    let filtered_responses: Vec<&Value> = if let Some(cmd_id) = command_id {
        responses
            .iter()
            .filter(|r| r.get("command_id").and_then(|id| id.as_str()) == Some(&cmd_id))
            .take(limit as usize)
            .collect()
    } else {
        responses.iter().rev().take(limit as usize).collect()
    };

    let response = serde_json::json!({
        "responses": filtered_responses,
        "total": responses.len()
    });

    Ok(json_response(response, StatusCode::OK))
}

pub async fn api_clients_update_sysinfo(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if !is_authorized(&req) {
        return Ok(unauthorized());
    }
    let client_id = parse_query_param(&req, "client_id");
    if client_id.is_none() {
        return Ok(json_response(
            json!({"error": "client_id parameter is required"}),
            StatusCode::BAD_REQUEST,
        ));
    }
    let client_id = client_id.unwrap();

    let command_id = format!("cmd_{}", unix_time());
    let command = Command {
        id: command_id.clone(),
        command_type: "update_system_info".to_string(),
        parameters: vec![],
        timestamp: unix_time(),
        auth_token: AUTH_TOKEN.to_string(),
    };

    state.command_queue.lock().await.push(command.clone());
    state.activity_log.lock().await.push(LogEntry {
        timestamp: unix_time(),
        level: "INFO".to_string(),
        message: "System info update requested".to_string(),
        client_id: Some(client_id.clone()),
        command_id: Some(command_id.clone()),
        details: None,
    });

    Ok(json_response(
        json!({
            "status": "System info update requested",
            "command_id": command_id,
            "client_id": client_id
        }),
        StatusCode::OK,
    ))
}

/// 暗号化データアップロードエンドポイント
pub async fn api_encrypted_data_upload(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if !is_authorized(&req) {
        return Ok(unauthorized());
    }

    match extract_json_body(req).await {
        Ok(data) => {
            let client_id = data
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let data_type = data
                .get("data_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let filename = data
                .get("filename")
                .and_then(|v| v.as_str());

            // Base64エンコードされた暗号化データとラップ鍵を取得
            let encrypted_data_b64 = data.get("encrypted_data")
                .and_then(|v| v.as_str());
            let wrapped_key_b64 = data.get("wrapped_key")
                .and_then(|v| v.as_str());

            if let (Some(enc_data_b64), Some(key_data_b64)) = (encrypted_data_b64, wrapped_key_b64) {
                // Base64デコード
                use base64::{engine::general_purpose, Engine as _};
                match (general_purpose::STANDARD.decode(enc_data_b64), general_purpose::STANDARD.decode(key_data_b64)) {
                    (Ok(encrypted_data), Ok(wrapped_key)) => {
                        // 暗号化データを処理
                        match state.crypto.process_encrypted_upload(
                            client_id,
                            &encrypted_data,
                            &wrapped_key,
                            data_type,
                        ) {
                            Ok(decrypted_data) => {
                                let log_msg = if let Some(fname) = filename {
                                    format!("Encrypted data processed successfully: {} ({} bytes decrypted)", fname, decrypted_data.len())
                                } else {
                                    format!("Encrypted data processed successfully: {} bytes decrypted", decrypted_data.len())
                                };

                                let mut log_data = json!({
                                    "data_type": data_type,
                                    "encrypted_size": encrypted_data.len(),
                                    "decrypted_size": decrypted_data.len()
                                });
                                if let Some(fname) = filename {
                                    log_data["filename"] = json!(fname);
                                }

                                log_activity(
                                    state,
                                    "SUCCESS",
                                    &log_msg,
                                    Some(client_id),
                                    None,
                                    Some(log_data),
                                ).await;

                                if let Some(fname) = filename {
                                    println!("✅ Encrypted data processed successfully from {}: {} - {} ({} bytes)", 
                                        client_id, fname, data_type, decrypted_data.len());
                                } else {
                                    println!("✅ Encrypted data processed successfully from {}: {} ({} bytes)", 
                                        client_id, data_type, decrypted_data.len());
                                }

                                let mut response_data = json!({
                                    "status": "success",
                                    "message": "Encrypted data processed successfully",
                                    "client_id": client_id,
                                    "data_type": data_type,
                                    "decrypted_size": decrypted_data.len()
                                });
                                if let Some(fname) = filename {
                                    response_data["filename"] = json!(fname);
                                }

                                Ok(json_response(response_data, StatusCode::OK))
                            }
                            Err(e) => {
                                log_activity(
                                    state,
                                    "ERROR",
                                    &format!("Failed to process encrypted data: {}", e),
                                    Some(client_id),
                                    None,
                                    Some(json!({
                                        "error": e.to_string(),
                                        "data_type": data_type
                                    })),
                                ).await;

                                println!("❌ Failed to process encrypted data from {}: {}", client_id, e);

                                Ok(json_response(
                                    json!({
                                        "error": "Failed to process encrypted data",
                                        "details": e.to_string()
                                    }),
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                ))
                            }
                        }
                    }
                    _ => {
                        println!("❌ Base64 decode failed for encrypted data from {}", client_id);
                        Ok(json_response(
                            json!({"error": "Invalid base64 encoding"}),
                            StatusCode::BAD_REQUEST,
                        ))
                    }
                }
            } else {
                println!("❌ Missing encrypted_data or wrapped_key from {}", client_id);
                Ok(json_response(
                    json!({"error": "Missing encrypted_data or wrapped_key fields"}),
                    StatusCode::BAD_REQUEST,
                ))
            }
        }
        Err(_) => {
            Ok(json_response(
                json!({"error": "Invalid JSON data"}),
                StatusCode::BAD_REQUEST,
            ))
        }
    }
}

/// 暗号化パッケージ一覧取得エンドポイント
pub async fn api_list_encrypted_packages(
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match state.crypto.list_packages() {
        Ok(packages) => {
            Ok(json_response(
                json!({
                    "packages": packages,
                    "count": packages.len()
                }),
                StatusCode::OK,
            ))
        }
        Err(e) => {
            println!("❌ Failed to list encrypted packages: {}", e);
            Ok(json_response(
                json!({
                    "error": "Failed to list packages",
                    "details": e.to_string()
                }),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

/// パッケージ復号化エンドポイント
pub async fn api_decrypt_package(
    req: Request<Incoming>,
    state: &AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if !is_authorized(&req) {
        return Ok(unauthorized());
    }

    match extract_json_body(req).await {
        Ok(data) => {
            let client_id = data.get("client_id").and_then(|v| v.as_str());
            let timestamp = data.get("timestamp").and_then(|v| v.as_u64());

            if let (Some(client_id), Some(timestamp)) = (client_id, timestamp) {
                // 指定されたクライアントとタイムスタンプのパッケージを検索
                match state.crypto.get_client_packages(client_id) {
                    Ok(packages) => {
                        if let Some(package) = packages.iter().find(|p| p.timestamp == timestamp) {
                            match state.crypto.decrypt_package(package) {
                                Ok(decrypted_data) => {
                                    // Base64エンコードして返す（大きなデータの場合は注意）
                                    use base64::{engine::general_purpose, Engine as _};
                                    let data_len = decrypted_data.len();
                                    let encoded_data = general_purpose::STANDARD.encode(&decrypted_data);
                                    
                                    Ok(json_response(
                                        json!({
                                            "status": "success",
                                            "client_id": package.client_id,
                                            "timestamp": package.timestamp,
                                            "data_type": package.metadata.data_type,
                                            "decrypted_data": encoded_data,
                                            "size": data_len
                                        }),
                                        StatusCode::OK,
                                    ))
                                }
                                Err(e) => {
                                    println!("❌ Failed to decrypt package: {}", e);
                                    Ok(json_response(
                                        json!({
                                            "error": "Failed to decrypt package",
                                            "details": e.to_string()
                                        }),
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                    ))
                                }
                            }
                        } else {
                            Ok(json_response(
                                json!({"error": "Package not found"}),
                                StatusCode::NOT_FOUND,
                            ))
                        }
                    }
                    Err(e) => {
                        println!("❌ Failed to get client packages: {}", e);
                        Ok(json_response(
                            json!({
                                "error": "Failed to get packages",
                                "details": e.to_string()
                            }),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ))
                    }
                }
            } else {
                Ok(json_response(
                    json!({"error": "Missing client_id or timestamp"}),
                    StatusCode::BAD_REQUEST,
                ))
            }
        }
        Err(_) => {
            Ok(json_response(
                json!({"error": "Invalid JSON data"}),
                StatusCode::BAD_REQUEST,
            ))
        }
    }
}
