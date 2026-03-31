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
    ReadonlyInputProbe,
    WritableOutputProbe,
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
            Self::NetworkIsolationProbe => {
                "test -r /proc/net/dev && test $(grep -Ec '^[[:space:]]*[^ :]+:' /proc/net/dev) -le 1"
            }
            Self::IpcIsolationProbe => {
                "test -r /proc/sysvipc/shm && test $(wc -l < /proc/sysvipc/shm) -le 1 && test -r /proc/sysvipc/msg && test $(wc -l < /proc/sysvipc/msg) -le 1 && test -r /proc/sysvipc/sem && test $(wc -l < /proc/sysvipc/sem) -le 1"
            }
            Self::UserNamespaceProbe => "id -u && id -g",
            Self::ReadonlyInputProbe => {
                "cat /inputs/input.txt && ! printf 'tamper' >> /inputs/input.txt"
            }
            Self::WritableOutputProbe => {
                "printf 'result' > /output/result.txt && cat /output/result.txt"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaliciousScenario {
    HostFilesystemEscape,
    ProcInfoLeakProbe,
    ReadonlyInputTamper,
    StrictSocketCreation,
    DefaultPtraceProbe,
}

impl MaliciousScenario {
    pub fn id(self) -> &'static str {
        match self {
            Self::HostFilesystemEscape => "host_filesystem_escape",
            Self::ProcInfoLeakProbe => "proc_info_leak_probe",
            Self::ReadonlyInputTamper => "readonly_input_tamper",
            Self::StrictSocketCreation => "strict_socket_creation",
            Self::DefaultPtraceProbe => "default_ptrace_probe",
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Self::HostFilesystemEscape => "attempt to read a host-only file after rootfs isolation",
            Self::ProcInfoLeakProbe => "attempt to inspect process information through /proc",
            Self::ReadonlyInputTamper => "attempt to overwrite a readonly input file",
            Self::StrictSocketCreation => "attempt to create a network socket under strict seccomp",
            Self::DefaultPtraceProbe => "attempt to call ptrace under the default seccomp profile",
        }
    }

    pub fn expected_guardrail(self) -> &'static str {
        match self {
            Self::HostFilesystemEscape => "chroot/rootfs visibility isolation",
            Self::ProcInfoLeakProbe => "minimal /proc mount inside pid namespace",
            Self::ReadonlyInputTamper => "readonly bind mount policy",
            Self::StrictSocketCreation => "strict seccomp socket deny rule",
            Self::DefaultPtraceProbe => "default seccomp ptrace deny rule",
        }
    }

    pub fn argv(self) -> Vec<String> {
        match self {
            Self::HostFilesystemEscape => vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                Scenario::HostVisibilityProbe.shell_snippet().to_string(),
            ],
            Self::ProcInfoLeakProbe => vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                Scenario::ProcVisibilityProbe.shell_snippet().to_string(),
            ],
            Self::ReadonlyInputTamper => vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                Scenario::ReadonlyInputProbe.shell_snippet().to_string(),
            ],
            Self::StrictSocketCreation => vec![
                "/usr/bin/python3".to_string(),
                "-c".to_string(),
                "import socket; exec(\"try:\\n socket.socket(socket.AF_INET, socket.SOCK_STREAM)\\n raise SystemExit(1)\\nexcept OSError as err:\\n print(err.errno)\\n raise SystemExit(0 if err.errno == 1 else 2)\")"
                    .to_string(),
            ],
            Self::DefaultPtraceProbe => vec![
                "/usr/bin/python3".to_string(),
                "-c".to_string(),
                "import ctypes; libc = ctypes.CDLL(None, use_errno=True); result = libc.ptrace(0, 0, None, 0); err = ctypes.get_errno(); print(result); print(err); raise SystemExit(0 if result == -1 and err == 1 else 1)"
                    .to_string(),
            ],
        }
    }
}

pub fn malicious_scenarios() -> &'static [MaliciousScenario] {
    &[
        MaliciousScenario::HostFilesystemEscape,
        MaliciousScenario::ProcInfoLeakProbe,
        MaliciousScenario::ReadonlyInputTamper,
        MaliciousScenario::StrictSocketCreation,
        MaliciousScenario::DefaultPtraceProbe,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StressScenario {
    EchoBurst,
    WorkDirRoundTrip,
    CpuBoundSuccess,
}

impl StressScenario {
    pub fn id(self) -> &'static str {
        match self {
            Self::EchoBurst => "echo_burst",
            Self::WorkDirRoundTrip => "workdir_round_trip",
            Self::CpuBoundSuccess => "cpu_bound_success",
        }
    }

    pub fn argv(self) -> Vec<String> {
        match self {
            Self::EchoBurst => vec!["/bin/echo".to_string(), "stress-ok".to_string()],
            Self::WorkDirRoundTrip => vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf 'stress' > /work/stress.txt && cat /work/stress.txt".to_string(),
            ],
            Self::CpuBoundSuccess => ResourceScenario::CpuBoundSuccess.argv(),
        }
    }
}

pub fn stress_scenarios() -> &'static [StressScenario] {
    &[
        StressScenario::EchoBurst,
        StressScenario::WorkDirRoundTrip,
        StressScenario::CpuBoundSuccess,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceScenario {
    ForkBombProbe,
    SmallProcessTree,
    CpuBusyLoop,
    CpuBoundSuccess,
    MemoryBomb,
    MemoryWithinLimit,
}

impl ResourceScenario {
    pub fn python_snippet(self) -> &'static str {
        match self {
            Self::ForkBombProbe => {
                "import errno, os; exec(\"try:\\n os.fork()\\n raise SystemExit(1)\\nexcept OSError as err:\\n print(err.errno)\\n raise SystemExit(0 if err.errno in (errno.EAGAIN, errno.ENOMEM) else 2)\")"
            }
            Self::SmallProcessTree => {
                "import os; exec(\"pid = os.fork()\\nif pid == 0:\\n raise SystemExit(0)\\nended_pid, status = os.waitpid(pid, 0)\\nprint(ended_pid > 0)\\nraise SystemExit(0 if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 else 1)\")"
            }
            Self::CpuBusyLoop => "while True: pass",
            Self::CpuBoundSuccess => {
                "total = 0\nfor i in range(500000):\n total += i\nprint(total > 0)"
            }
            Self::MemoryBomb => {
                "chunks = []; chunk = b'x' * (1024 * 1024); exec(\"while True:\\n chunks.append(chunk[:])\")"
            }
            Self::MemoryWithinLimit => "buf = bytearray(1024 * 1024); print(len(buf))",
        }
    }

    pub fn argv(self) -> Vec<String> {
        vec![
            "/usr/bin/python3".to_string(),
            "-c".to_string(),
            self.python_snippet().to_string(),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompScenario {
    ShellRuntime,
    PythonRuntime,
}

impl SeccompScenario {
    pub fn argv(self) -> Vec<String> {
        match self {
            Self::ShellRuntime => vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "set -eu; value=$(printf 'shell-ok'); [ \"$value\" = 'shell-ok' ]; printf '%s\\n' \"$value\""
                    .to_string(),
            ],
            Self::PythonRuntime => vec![
                "/usr/bin/python3".to_string(),
                "-c".to_string(),
                "import hashlib, json, subprocess; digest = hashlib.sha256(b'sandbox').hexdigest()[:8]; completed = subprocess.run(['/bin/echo', digest], check=True, capture_output=True, text=True); payload = json.loads(json.dumps({'digest': completed.stdout.strip()})); print(payload['digest'])"
                    .to_string(),
            ],
        }
    }
}

pub fn roadmap() -> &'static str {
    "M6 scaffold: add malicious samples, regression fixtures, and pressure scenarios."
}

#[cfg(test)]
mod tests {
    use super::{ResourceScenario, SeccompScenario, malicious_scenarios, stress_scenarios};

    #[test]
    fn resource_scenarios_emit_python_commands() {
        for scenario in [
            ResourceScenario::ForkBombProbe,
            ResourceScenario::SmallProcessTree,
            ResourceScenario::CpuBusyLoop,
            ResourceScenario::CpuBoundSuccess,
            ResourceScenario::MemoryBomb,
            ResourceScenario::MemoryWithinLimit,
        ] {
            let argv = scenario.argv();
            assert_eq!(argv[0], "/usr/bin/python3");
            assert_eq!(argv[1], "-c");
            assert!(!argv[2].trim().is_empty());
        }
    }

    #[test]
    fn seccomp_scenarios_emit_commands() {
        for scenario in [
            SeccompScenario::ShellRuntime,
            SeccompScenario::PythonRuntime,
        ] {
            let argv = scenario.argv();
            assert!(!argv.is_empty());
            assert!(!argv[0].trim().is_empty());
            assert!(!argv[argv.len() - 1].trim().is_empty());
        }
    }

    #[test]
    fn malicious_scenarios_have_metadata_and_commands() {
        for scenario in malicious_scenarios() {
            let argv = scenario.argv();
            assert!(!scenario.id().trim().is_empty());
            assert!(!scenario.summary().trim().is_empty());
            assert!(!scenario.expected_guardrail().trim().is_empty());
            assert!(!argv.is_empty());
            assert!(!argv[0].trim().is_empty());
            assert!(!argv[argv.len() - 1].trim().is_empty());
        }
    }

    #[test]
    fn stress_scenarios_emit_commands() {
        for scenario in stress_scenarios() {
            let argv = scenario.argv();
            assert!(!scenario.id().trim().is_empty());
            assert!(!argv.is_empty());
            assert!(!argv[0].trim().is_empty());
            assert!(!argv[argv.len() - 1].trim().is_empty());
        }
    }
}
