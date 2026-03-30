use sandbox_config::ExecutionConfig;
use sandbox_core::ExecutionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub request_id: String,
    pub config: ExecutionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub stage: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub request: ExecutionRequest,
    pub result: ExecutionResult,
    pub audit_events: Vec<AuditEvent>,
}
