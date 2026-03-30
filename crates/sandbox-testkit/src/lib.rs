#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Echo,
    Timeout,
    RuntimeError,
}

impl Scenario {
    pub fn shell_snippet(self) -> &'static str {
        match self {
            Self::Echo => "printf 'hello\\n'",
            Self::Timeout => "sleep 5",
            Self::RuntimeError => "exit 42",
        }
    }
}

pub fn roadmap() -> &'static str {
    "M6 scaffold: add malicious samples, regression fixtures, and pressure scenarios."
}
