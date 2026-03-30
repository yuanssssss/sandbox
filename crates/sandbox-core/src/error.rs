use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("required sandbox capability `{capability}` is unavailable: {detail}")]
    CapabilityUnavailable {
        capability: &'static str,
        detail: String,
    },
    #[error("permission isolation setup failed: {0}")]
    Permission(String),
    #[error("I/O error while {context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to spawn process: {0}")]
    Spawn(String),
    #[error("sandbox timeout after {wall_time_ms}ms")]
    Timeout { wall_time_ms: u64 },
    #[error("cleanup failed: {0}")]
    Cleanup(String),
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(&'static str),
    #[error("sandbox internal error: {0}")]
    Internal(String),
}

impl SandboxError {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn capability_unavailable(capability: &'static str, detail: impl Into<String>) -> Self {
        Self::CapabilityUnavailable {
            capability,
            detail: detail.into(),
        }
    }

    pub fn permission(message: impl Into<String>) -> Self {
        Self::Permission(message.into())
    }

    pub fn io(context: &'static str, source: std::io::Error) -> Self {
        Self::Io { context, source }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

pub type Result<T> = std::result::Result<T, SandboxError>;
