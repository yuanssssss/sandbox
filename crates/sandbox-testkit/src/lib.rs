#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Echo,
    Timeout,
    RuntimeError,
    WorkDirWriteProbe,
    HostVisibilityProbe,
    ProcVisibilityProbe,
    NetworkIsolationProbe,
    IpcIsolationProbe,
    UserNamespaceProbe,
}

impl Scenario {
    pub fn shell_snippet(self) -> &'static str {
        match self {
            Self::Echo => "printf 'hello\\n'",
            Self::Timeout => "sleep 5",
            Self::RuntimeError => "exit 42",
            Self::WorkDirWriteProbe => "pwd && touch /work/probe.txt && test -f /work/probe.txt",
            Self::HostVisibilityProbe => "test ! -e /host-secret.txt",
            Self::ProcVisibilityProbe => "test -d /proc && test -r /proc/self/status",
            Self::NetworkIsolationProbe => "test ! -e /proc/net/dev",
            Self::IpcIsolationProbe => "test -w /proc/sysvipc || test ! -e /proc/sysvipc",
            Self::UserNamespaceProbe => "id -u && id -g",
        }
    }
}

pub fn roadmap() -> &'static str {
    "M6 scaffold: add malicious samples, regression fixtures, and pressure scenarios."
}
