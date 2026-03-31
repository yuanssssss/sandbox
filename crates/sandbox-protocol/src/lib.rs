use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::Path;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use sandbox_config::ExecutionConfig;
use sandbox_core::{ExecutionResult, ResourceLimits, SandboxError};
use sandbox_supervisor::{NamespaceSupport, RunOptions, probe_namespace_support, run};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

pub type BackendFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub trait ProtocolBackend: Send + Sync + 'static {
    fn health(&self) -> BackendFuture<HealthStatus>;
    fn capabilities(&self) -> BackendFuture<CapabilitiesResponse>;
    fn validate_config(
        &self,
        request: ValidateConfigRequest,
    ) -> BackendFuture<Result<ValidateConfigResponse, ProtocolError>>;
    fn execute(
        &self,
        request: ExecutionRequest,
    ) -> BackendFuture<Result<ExecutionReport, ProtocolError>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub request_id: String,
    pub config: ExecutionConfig,
    #[serde(default)]
    pub command_override: Option<Vec<String>>,
    #[serde(default)]
    pub artifact_dir: Option<std::path::PathBuf>,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTaskStatus {
    Accepted,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTaskAccepted {
    pub task_id: String,
    pub request_id: String,
    pub status: ExecutionTaskStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTaskResponse {
    pub task_id: String,
    pub request_id: String,
    pub status: ExecutionTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ExecutionReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub service: String,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            status: "ok".to_string(),
            service: "sandbox-protocol".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityStatus {
    pub available: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesResponse {
    pub user_namespace: CapabilityStatus,
    pub mount_namespace: CapabilityStatus,
    pub pid_namespace: CapabilityStatus,
    pub network_namespace: CapabilityStatus,
    pub ipc_namespace: CapabilityStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateConfigRequest {
    pub config: ExecutionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateConfigResponse {
    pub valid: bool,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProtocolError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub request_id: Option<String>,
}

impl ProtocolError {
    pub fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            request_id,
        }
    }
}

impl From<SandboxError> for ProtocolError {
    fn from(value: SandboxError) -> Self {
        match value {
            SandboxError::Config(message) => {
                Self::new(StatusCode::BAD_REQUEST, "configuration", message, None)
            }
            SandboxError::CapabilityUnavailable { capability, detail } => Self::new(
                StatusCode::CONFLICT,
                "capability_unavailable",
                format!("required sandbox capability `{capability}` is unavailable: {detail}"),
                None,
            ),
            SandboxError::Permission(message) => {
                Self::new(StatusCode::FORBIDDEN, "permission_isolation", message, None)
            }
            SandboxError::Io { context, source } => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "io",
                format!("I/O error while {context}: {source}"),
                None,
            ),
            SandboxError::Spawn(message) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "spawn", message, None)
            }
            SandboxError::Timeout { wall_time_ms } => Self::new(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                format!("sandbox timeout after {wall_time_ms}ms"),
                None,
            ),
            SandboxError::Cleanup(message) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "cleanup", message, None)
            }
            SandboxError::UnsupportedPlatform(message) => Self::new(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_platform",
                message,
                None,
            ),
            SandboxError::Internal(message) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message, None)
            }
        }
    }
}

impl IntoResponse for ProtocolError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            error: ErrorDetail {
                code: self.code.to_string(),
                message: self.message,
                request_id: self.request_id,
            },
        });
        (self.status, body).into_response()
    }
}

fn json_rejection_to_protocol_error(rejection: JsonRejection) -> ProtocolError {
    match rejection {
        JsonRejection::MissingJsonContentType(_) => ProtocolError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_content_type",
            "request content type must be application/json",
            None,
        ),
        JsonRejection::JsonSyntaxError(_) => ProtocolError::new(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "request body contains invalid JSON",
            None,
        ),
        JsonRejection::JsonDataError(_) => ProtocolError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request body does not match the protocol schema",
            None,
        ),
        JsonRejection::BytesRejection(_) => ProtocolError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_body",
            "request body could not be read",
            None,
        ),
        _ => ProtocolError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request body could not be decoded",
            None,
        ),
    }
}

fn not_found_error() -> ProtocolError {
    ProtocolError::new(StatusCode::NOT_FOUND, "not_found", "route not found", None)
}

fn method_not_allowed_error() -> ProtocolError {
    ProtocolError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "method not allowed for this route",
        None,
    )
}

fn task_not_found_error(task_id: &str) -> ProtocolError {
    ProtocolError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("execution task `{task_id}` was not found"),
        None,
    )
}

fn error_detail_from_protocol_error(
    error: ProtocolError,
    fallback_request_id: Option<String>,
) -> ErrorDetail {
    ErrorDetail {
        code: error.code.to_string(),
        message: error.message,
        request_id: error.request_id.or(fallback_request_id),
    }
}

struct ExecutionTaskManager<B> {
    backend: Arc<B>,
    next_task_id: AtomicU64,
    tasks: Arc<RwLock<HashMap<String, ExecutionTaskResponse>>>,
}

impl<B> ExecutionTaskManager<B>
where
    B: ProtocolBackend,
{
    fn new(backend: Arc<B>) -> Self {
        Self {
            backend,
            next_task_id: AtomicU64::new(1),
            tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn submit(
        &self,
        request: ExecutionRequest,
    ) -> Result<ExecutionTaskAccepted, ProtocolError> {
        let request_id = request.request_id.clone();
        self.backend
            .validate_config(ValidateConfigRequest {
                config: request.config.clone(),
            })
            .await
            .map_err(|mut err| {
                if err.request_id.is_none() {
                    err.request_id = Some(request_id.clone());
                }
                err
            })?;

        let task_id = format!("exec-{}", self.next_task_id.fetch_add(1, Ordering::Relaxed));
        let accepted = ExecutionTaskAccepted {
            task_id: task_id.clone(),
            request_id: request_id.clone(),
            status: ExecutionTaskStatus::Accepted,
        };

        self.tasks.write().await.insert(
            task_id.clone(),
            ExecutionTaskResponse {
                task_id: task_id.clone(),
                request_id: request_id.clone(),
                status: ExecutionTaskStatus::Accepted,
                report: None,
                error: None,
            },
        );

        let backend = Arc::clone(&self.backend);
        let tasks = Arc::clone(&self.tasks);
        tokio::spawn(async move {
            update_task_status(&tasks, &task_id, ExecutionTaskStatus::Running, None, None).await;
            match backend.execute(request).await {
                Ok(report) => {
                    update_task_status(
                        &tasks,
                        &task_id,
                        ExecutionTaskStatus::Completed,
                        Some(report),
                        None,
                    )
                    .await;
                }
                Err(error) => {
                    let detail = error_detail_from_protocol_error(error, Some(request_id));
                    update_task_status(
                        &tasks,
                        &task_id,
                        ExecutionTaskStatus::Failed,
                        None,
                        Some(detail),
                    )
                    .await;
                }
            }
        });

        Ok(accepted)
    }

    async fn get(&self, task_id: &str) -> Option<ExecutionTaskResponse> {
        self.tasks.read().await.get(task_id).cloned()
    }
}

async fn update_task_status(
    tasks: &RwLock<HashMap<String, ExecutionTaskResponse>>,
    task_id: &str,
    status: ExecutionTaskStatus,
    report: Option<ExecutionReport>,
    error: Option<ErrorDetail>,
) {
    let mut guard = tasks.write().await;
    if let Some(task) = guard.get_mut(task_id) {
        task.status = status;
        task.report = report;
        task.error = error;
    }
}

pub fn build_router<B>(backend: B) -> Router
where
    B: ProtocolBackend,
{
    let backend = Arc::new(backend);
    let health_backend = Arc::clone(&backend);
    let capabilities_backend = Arc::clone(&backend);
    let validate_backend = Arc::clone(&backend);
    let execute_backend = Arc::clone(&backend);
    let async_submit_manager = Arc::new(ExecutionTaskManager::new(Arc::clone(&backend)));
    let async_status_manager = Arc::clone(&async_submit_manager);

    Router::new()
        .route(
            "/healthz",
            get(move || {
                let backend = Arc::clone(&health_backend);
                async move { Json(backend.health().await) }
            }),
        )
        .route(
            "/api/v1/capabilities",
            get(move || {
                let backend = Arc::clone(&capabilities_backend);
                async move { Json(backend.capabilities().await) }
            }),
        )
        .route(
            "/api/v1/config/validate",
            post(
                move |payload: Result<Json<ValidateConfigRequest>, JsonRejection>| {
                    let backend = Arc::clone(&validate_backend);
                    async move {
                        let Json(request) = payload.map_err(json_rejection_to_protocol_error)?;
                        backend.validate_config(request).await.map(Json)
                    }
                },
            ),
        )
        .route(
            "/api/v1/executions",
            post(
                move |payload: Result<Json<ExecutionRequest>, JsonRejection>| {
                    let backend = Arc::clone(&execute_backend);
                    async move {
                        let Json(request) = payload.map_err(json_rejection_to_protocol_error)?;
                        backend.execute(request).await.map(Json)
                    }
                },
            ),
        )
        .route(
            "/api/v1/executions/async",
            post(
                move |payload: Result<Json<ExecutionRequest>, JsonRejection>| {
                    let manager = Arc::clone(&async_submit_manager);
                    async move {
                        let Json(request) = payload.map_err(json_rejection_to_protocol_error)?;
                        manager
                            .submit(request)
                            .await
                            .map(|accepted| (StatusCode::ACCEPTED, Json(accepted)))
                    }
                },
            ),
        )
        .route(
            "/api/v1/executions/{task_id}",
            get(move |Path(task_id): Path<String>| {
                let manager = Arc::clone(&async_status_manager);
                async move {
                    manager
                        .get(&task_id)
                        .await
                        .ok_or_else(|| task_not_found_error(&task_id))
                        .map(Json)
                }
            }),
        )
        .method_not_allowed_fallback(|| async { method_not_allowed_error() })
        .fallback(|| async { not_found_error() })
}

pub fn default_router() -> Router {
    build_router(SupervisorBackend)
}

pub async fn serve(addr: SocketAddr) -> std::io::Result<()> {
    info!(%addr, "starting sandbox protocol server");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, default_router()).await
}

#[derive(Debug, Clone, Default)]
pub struct SupervisorBackend;

impl ProtocolBackend for SupervisorBackend {
    fn health(&self) -> BackendFuture<HealthStatus> {
        Box::pin(async { HealthStatus::default() })
    }

    fn capabilities(&self) -> BackendFuture<CapabilitiesResponse> {
        Box::pin(async { CapabilitiesResponse::from(probe_namespace_support()) })
    }

    fn validate_config(
        &self,
        request: ValidateConfigRequest,
    ) -> BackendFuture<Result<ValidateConfigResponse, ProtocolError>> {
        Box::pin(async move {
            request.config.validate().map_err(ProtocolError::from)?;
            Ok(ValidateConfigResponse {
                valid: true,
                resource_limits: request.config.resource_limits(),
            })
        })
    }

    fn execute(
        &self,
        request: ExecutionRequest,
    ) -> BackendFuture<Result<ExecutionReport, ProtocolError>> {
        Box::pin(async move {
            let request_id = request.request_id.clone();
            request.config.validate().map_err(|err| {
                let mut mapped = ProtocolError::from(err);
                mapped.request_id = Some(request_id.clone());
                mapped
            })?;

            let run_request = request.clone();
            let result = tokio::task::spawn_blocking(move || {
                run(
                    &run_request.config,
                    &RunOptions {
                        argv_override: run_request.command_override.clone(),
                        artifact_dir: run_request.artifact_dir.clone(),
                        cgroup_root_override: None,
                    },
                )
            })
            .await
            .map_err(|err| {
                ProtocolError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    format!("sandbox execution task failed to join: {err}"),
                    Some(request_id.clone()),
                )
            })?
            .map_err(|err| {
                let mut mapped = ProtocolError::from(err);
                mapped.request_id = Some(request_id.clone());
                mapped
            })?;

            Ok(ExecutionReport {
                request,
                result,
                audit_events: vec![
                    AuditEvent {
                        stage: "accepted".to_string(),
                        message: "execution request accepted".to_string(),
                    },
                    AuditEvent {
                        stage: "completed".to_string(),
                        message: "execution finished".to_string(),
                    },
                ],
            })
        })
    }
}

impl From<NamespaceSupport> for CapabilitiesResponse {
    fn from(value: NamespaceSupport) -> Self {
        Self {
            user_namespace: CapabilityStatus {
                available: value.user_namespace,
                reason: value.user_reason,
            },
            mount_namespace: CapabilityStatus {
                available: value.mount_namespace,
                reason: value.mount_reason,
            },
            pid_namespace: CapabilityStatus {
                available: value.pid_namespace,
                reason: value.pid_reason,
            },
            network_namespace: CapabilityStatus {
                available: value.network_namespace,
                reason: value.network_reason,
            },
            ipc_namespace: CapabilityStatus {
                available: value.ipc_namespace,
                reason: value.ipc_reason,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use sandbox_core::{ExecutionStatus, ResourceUsage};
    use serde::de::DeserializeOwned;
    use tokio::sync::Notify;
    use tower::util::ServiceExt;

    #[derive(Clone)]
    struct TestBackend;

    impl ProtocolBackend for TestBackend {
        fn health(&self) -> BackendFuture<HealthStatus> {
            Box::pin(async { HealthStatus::default() })
        }

        fn capabilities(&self) -> BackendFuture<CapabilitiesResponse> {
            Box::pin(async {
                CapabilitiesResponse {
                    user_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    mount_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    pid_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    network_namespace: CapabilityStatus {
                        available: false,
                        reason: Some("disabled in test".to_string()),
                    },
                    ipc_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                }
            })
        }

        fn validate_config(
            &self,
            request: ValidateConfigRequest,
        ) -> BackendFuture<Result<ValidateConfigResponse, ProtocolError>> {
            Box::pin(async move {
                request.config.validate().map_err(ProtocolError::from)?;
                Ok(ValidateConfigResponse {
                    valid: true,
                    resource_limits: request.config.resource_limits(),
                })
            })
        }

        fn execute(
            &self,
            request: ExecutionRequest,
        ) -> BackendFuture<Result<ExecutionReport, ProtocolError>> {
            Box::pin(async move {
                if request.request_id == "bad" {
                    return Err(ProtocolError::new(
                        StatusCode::BAD_REQUEST,
                        "configuration",
                        "bad request",
                        Some(request.request_id),
                    ));
                }

                Ok(ExecutionReport {
                    request: request.clone(),
                    result: ExecutionResult {
                        command: request
                            .command_override
                            .clone()
                            .unwrap_or_else(|| request.config.process.argv.clone()),
                        exit_code: Some(0),
                        term_signal: None,
                        usage: ResourceUsage {
                            cpu_time_ms: Some(1),
                            wall_time_ms: 2,
                            memory_peak_bytes: Some(3),
                        },
                        stdout_path: "stdout.log".into(),
                        stderr_path: "stderr.log".into(),
                        status: ExecutionStatus::Ok,
                    },
                    audit_events: vec![AuditEvent {
                        stage: "completed".to_string(),
                        message: "test finished".to_string(),
                    }],
                })
            })
        }
    }

    fn sample_config() -> ExecutionConfig {
        ExecutionConfig::from_toml_str(
            r#"
[process]
argv = ["/bin/echo", "hello"]

[limits]
wall_time_ms = 1000

[filesystem]
enable_rootfs = false
"#,
        )
        .expect("config should parse")
    }

    async fn response_json<T: DeserializeOwned>(response: Response) -> T {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        serde_json::from_slice(&bytes).expect("response body should be valid JSON")
    }

    async fn send(app: &Router, request: Request<Body>) -> Response {
        app.clone()
            .oneshot(request)
            .await
            .expect("router request should succeed")
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: HealthStatus = response_json(response).await;
        assert_eq!(body.status, "ok");
        assert_eq!(body.service, "sandbox-protocol");
    }

    #[tokio::test]
    async fn capabilities_returns_backend_payload() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .uri("/api/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: CapabilitiesResponse = response_json(response).await;
        assert!(body.user_namespace.available);
        assert!(!body.network_namespace.available);
        assert_eq!(
            body.network_namespace.reason.as_deref(),
            Some("disabled in test")
        );
    }

    #[tokio::test]
    async fn validate_config_returns_limits() {
        let app = build_router(TestBackend);
        let payload = serde_json::to_vec(&ValidateConfigRequest {
            config: sample_config(),
        })
        .unwrap();
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/validate")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: ValidateConfigResponse = response_json(response).await;
        assert!(body.valid);
        assert_eq!(body.resource_limits, sample_config().resource_limits());
    }

    #[tokio::test]
    async fn validate_config_rejects_missing_json_content_type() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/validate")
                .body(Body::from(
                    serde_json::to_vec(&ValidateConfigRequest {
                        config: sample_config(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "invalid_content_type");
        assert_eq!(
            body.error.message,
            "request content type must be application/json"
        );
        assert_eq!(body.error.request_id, None);
    }

    #[tokio::test]
    async fn execute_returns_report() {
        let app = build_router(TestBackend);
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "run-001".to_string(),
            config: sample_config(),
            command_override: Some(vec!["/bin/echo".to_string(), "override".to_string()]),
            artifact_dir: Some("/tmp/sandbox-api/run-001".into()),
        })
        .unwrap();
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: ExecutionReport = response_json(response).await;
        assert_eq!(body.request.request_id, "run-001");
        assert_eq!(
            body.result.command,
            vec!["/bin/echo".to_string(), "override".to_string()]
        );
        assert_eq!(body.result.status, ExecutionStatus::Ok);
        assert_eq!(body.audit_events.len(), 1);
        assert_eq!(body.audit_events[0].stage, "completed");
    }

    #[tokio::test]
    async fn execute_rejects_malformed_json() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "invalid_json");
        assert_eq!(body.error.message, "request body contains invalid JSON");
        assert_eq!(body.error.request_id, None);
    }

    #[tokio::test]
    async fn execute_maps_backend_errors() {
        let app = build_router(TestBackend);
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "bad".to_string(),
            config: sample_config(),
            command_override: None,
            artifact_dir: None,
        })
        .unwrap();
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "configuration");
        assert_eq!(body.error.message, "bad request");
        assert_eq!(body.error.request_id.as_deref(), Some("bad"));
    }

    #[tokio::test]
    async fn unknown_route_returns_protocol_error() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .uri("/api/v1/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "not_found");
        assert_eq!(body.error.message, "route not found");
        assert_eq!(body.error.request_id, None);
    }

    #[tokio::test]
    async fn unsupported_method_returns_protocol_error() {
        let app = build_router(TestBackend);
        let response = send(
            &app,
            Request::builder()
                .method("GET")
                .uri("/api/v1/executions")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "method_not_allowed");
        assert_eq!(body.error.message, "method not allowed for this route");
        assert_eq!(body.error.request_id, None);
    }

    #[derive(Clone)]
    struct GatedBackend {
        gate: Arc<Notify>,
        started: Arc<Notify>,
        fail: bool,
    }

    impl GatedBackend {
        fn success() -> Self {
            Self {
                gate: Arc::new(Notify::new()),
                started: Arc::new(Notify::new()),
                fail: false,
            }
        }

        fn failure() -> Self {
            Self {
                gate: Arc::new(Notify::new()),
                started: Arc::new(Notify::new()),
                fail: true,
            }
        }
    }

    impl ProtocolBackend for GatedBackend {
        fn health(&self) -> BackendFuture<HealthStatus> {
            Box::pin(async { HealthStatus::default() })
        }

        fn capabilities(&self) -> BackendFuture<CapabilitiesResponse> {
            Box::pin(async {
                CapabilitiesResponse {
                    user_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    mount_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    pid_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                    network_namespace: CapabilityStatus {
                        available: false,
                        reason: Some("disabled in test".to_string()),
                    },
                    ipc_namespace: CapabilityStatus {
                        available: true,
                        reason: None,
                    },
                }
            })
        }

        fn validate_config(
            &self,
            request: ValidateConfigRequest,
        ) -> BackendFuture<Result<ValidateConfigResponse, ProtocolError>> {
            Box::pin(async move {
                request.config.validate().map_err(ProtocolError::from)?;
                Ok(ValidateConfigResponse {
                    valid: true,
                    resource_limits: request.config.resource_limits(),
                })
            })
        }

        fn execute(
            &self,
            request: ExecutionRequest,
        ) -> BackendFuture<Result<ExecutionReport, ProtocolError>> {
            let gate = Arc::clone(&self.gate);
            let started = Arc::clone(&self.started);
            let fail = self.fail;
            Box::pin(async move {
                started.notify_one();
                gate.notified().await;
                if fail {
                    return Err(ProtocolError::new(
                        StatusCode::CONFLICT,
                        "capability_unavailable",
                        "network namespace unavailable",
                        Some(request.request_id),
                    ));
                }

                Ok(ExecutionReport {
                    request: request.clone(),
                    result: ExecutionResult {
                        command: request
                            .command_override
                            .clone()
                            .unwrap_or_else(|| request.config.process.argv.clone()),
                        exit_code: Some(0),
                        term_signal: None,
                        usage: ResourceUsage {
                            cpu_time_ms: Some(1),
                            wall_time_ms: 2,
                            memory_peak_bytes: Some(3),
                        },
                        stdout_path: "stdout.log".into(),
                        stderr_path: "stderr.log".into(),
                        status: ExecutionStatus::Ok,
                    },
                    audit_events: vec![
                        AuditEvent {
                            stage: "accepted".to_string(),
                            message: "execution request accepted".to_string(),
                        },
                        AuditEvent {
                            stage: "completed".to_string(),
                            message: "execution finished".to_string(),
                        },
                    ],
                })
            })
        }
    }

    async fn fetch_task_response(app: &Router, task_id: &str) -> Response {
        send(
            app,
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/executions/{task_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn async_execute_returns_accepted_and_completed_status() {
        let backend = GatedBackend::success();
        let app = build_router(backend.clone());
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "async-run-001".to_string(),
            config: sample_config(),
            command_override: Some(vec!["/bin/echo".to_string(), "async".to_string()]),
            artifact_dir: Some("/tmp/sandbox-api/async-run-001".into()),
        })
        .unwrap();

        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions/async")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let accepted: ExecutionTaskAccepted = response_json(response).await;
        assert_eq!(accepted.request_id, "async-run-001");
        assert_eq!(accepted.status, ExecutionTaskStatus::Accepted);
        assert!(accepted.task_id.starts_with("exec-"));

        backend.started.notified().await;

        let running_response = fetch_task_response(&app, &accepted.task_id).await;
        assert_eq!(running_response.status(), StatusCode::OK);
        let running: ExecutionTaskResponse = response_json(running_response).await;
        assert_eq!(running.status, ExecutionTaskStatus::Running);
        assert!(running.report.is_none());
        assert!(running.error.is_none());

        backend.gate.notify_waiters();

        for _ in 0..20 {
            let completed_response = fetch_task_response(&app, &accepted.task_id).await;
            let completed: ExecutionTaskResponse = response_json(completed_response).await;
            if completed.status == ExecutionTaskStatus::Completed {
                assert_eq!(completed.request_id, "async-run-001");
                assert!(completed.error.is_none());
                assert_eq!(
                    completed
                        .report
                        .as_ref()
                        .map(|report| report.result.status.clone()),
                    Some(ExecutionStatus::Ok)
                );
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("async execution task did not complete in time");
    }

    #[tokio::test]
    async fn async_execute_persists_failures_in_task_status() {
        let backend = GatedBackend::failure();
        let app = build_router(backend.clone());
        let payload = serde_json::to_vec(&ExecutionRequest {
            request_id: "async-run-bad".to_string(),
            config: sample_config(),
            command_override: None,
            artifact_dir: None,
        })
        .unwrap();

        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/executions/async")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let accepted: ExecutionTaskAccepted = response_json(response).await;
        backend.started.notified().await;
        backend.gate.notify_waiters();

        for _ in 0..20 {
            let failed_response = fetch_task_response(&app, &accepted.task_id).await;
            let failed: ExecutionTaskResponse = response_json(failed_response).await;
            if failed.status == ExecutionTaskStatus::Failed {
                assert!(failed.report.is_none());
                assert_eq!(
                    failed.error.as_ref().map(|error| error.code.as_str()),
                    Some("capability_unavailable")
                );
                assert_eq!(
                    failed
                        .error
                        .as_ref()
                        .and_then(|error| error.request_id.as_deref()),
                    Some("async-run-bad")
                );
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("async execution task did not fail in time");
    }

    #[tokio::test]
    async fn async_status_returns_not_found_for_unknown_task() {
        let app = build_router(TestBackend);
        let response = fetch_task_response(&app, "missing-task").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: ErrorResponse = response_json(response).await;
        assert_eq!(body.error.code, "not_found");
        assert_eq!(
            body.error.message,
            "execution task `missing-task` was not found"
        );
        assert_eq!(body.error.request_id, None);
    }
}
