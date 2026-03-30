use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SeccompProfile {
    Default,
    Strict,
    Compat,
}

impl Default for SeccompProfile {
    fn default() -> Self {
        Self::Default
    }
}

#[derive(Debug, Error)]
pub enum SeccompError {
    #[error("seccomp profile `{0}` is not implemented yet")]
    UnimplementedProfile(&'static str),
}

pub fn install(profile: SeccompProfile) -> Result<(), SeccompError> {
    match profile {
        SeccompProfile::Default => Ok(()),
        SeccompProfile::Strict => Err(SeccompError::UnimplementedProfile("strict")),
        SeccompProfile::Compat => Err(SeccompError::UnimplementedProfile("compat")),
    }
}

pub fn roadmap() -> &'static str {
    "M4 scaffold: model seccomp profiles and install syscall filters as defense in depth."
}
