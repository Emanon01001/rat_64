use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Command {
    pub id: String,
    pub command_type: String,
    pub parameters: Vec<String>,
    pub timestamp: u64,
    pub auth_token: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: String,
    pub message: String,
    pub client_id: Option<String>,
    pub command_id: Option<String>,
    pub details: Option<Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientInfo {
    pub client_id: String,
    pub hostname: String,
    pub username: String,
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub cpu_info: String,
    pub timezone: String,
    pub is_virtual_machine: bool,
    pub virtual_machine_vendor: Option<String>,
    pub drives: Vec<DriveInfo>,
    pub last_seen: u64,
    pub status: String,
    pub public_ip: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DriveInfo {
    pub drive_letter: String,
    pub drive_type: String,
    pub total_space_gb: f64,
    pub free_space_gb: f64,
    pub file_system: String,
}
