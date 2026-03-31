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
    #[error("seccomp filter installation failed: {0}")]
    InstallFailed(String),
    #[error("seccomp filter is unsupported on this architecture")]
    UnsupportedArchitecture,
}

pub fn install(profile: SeccompProfile) -> Result<(), SeccompError> {
    match profile {
        SeccompProfile::Default => install_blacklist_filter(default_denied_syscalls()),
        SeccompProfile::Compat => install_blacklist_filter(compat_denied_syscalls()),
        SeccompProfile::Strict => install_blacklist_filter(strict_denied_syscalls()),
    }
}

fn install_blacklist_filter(denied_syscalls: &[i64]) -> Result<(), SeccompError> {
    set_no_new_privs()?;
    let program = build_filter_program(denied_syscalls)?;
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program as *const SockFprog,
        )
    };
    if result == -1 {
        return Err(SeccompError::InstallFailed(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

fn set_no_new_privs() -> Result<(), SeccompError> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(SeccompError::InstallFailed(format!(
                "setting no_new_privs failed: {err}"
            )));
        }
    }

    Ok(())
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

fn build_filter_program(denied_syscalls: &[i64]) -> Result<SockFprog, SeccompError> {
    let arch = audit_arch()?;
    let mut filters = Vec::with_capacity(4 + denied_syscalls.len() * 2);

    filters.push(stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 4));
    filters.push(jump(
        (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        arch,
        1,
        0,
    ));
    filters.push(stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        libc::SECCOMP_RET_KILL_PROCESS,
    ));
    filters.push(stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0));

    for syscall in denied_syscalls {
        filters.push(jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            *syscall as u32,
            0,
            1,
        ));
        filters.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));
    }

    filters.push(stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        libc::SECCOMP_RET_ALLOW,
    ));

    let boxed = filters.into_boxed_slice();
    let len = boxed.len() as u16;
    let filter = Box::into_raw(boxed) as *const SockFilter;
    Ok(SockFprog { len, filter })
}

fn audit_arch() -> Result<u32, SeccompError> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(0xc000_003e)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        Err(SeccompError::UnsupportedArchitecture)
    }
}

fn default_denied_syscalls() -> &'static [i64] {
    &[
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
    ]
}

fn compat_denied_syscalls() -> &'static [i64] {
    &[
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
    ]
}

fn strict_denied_syscalls() -> &'static [i64] {
    &[
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
    ]
}

pub fn roadmap() -> &'static str {
    "M4 scaffold: model seccomp profiles and install syscall filters as defense in depth."
}

#[cfg(test)]
mod tests {
    use super::{
        SeccompProfile, compat_denied_syscalls, default_denied_syscalls, install,
        strict_denied_syscalls,
    };

    #[test]
    fn default_filter_allows_basic_syscalls_and_blocks_ptrace() {
        let status = run_in_child(|| {
            install(SeccompProfile::Default).expect("default seccomp should install");

            let pid = unsafe { libc::getpid() };
            if pid <= 0 {
                return 1;
            }

            let ptrace_result = ptrace_traceme();
            if ptrace_result != -1 {
                return 2;
            }

            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                return 3;
            }

            0
        });

        assert_eq!(status, 0, "child should exit successfully");
    }

    #[test]
    fn compat_profile_keeps_ptrace_out_of_the_denylist() {
        assert!(
            !compat_denied_syscalls().contains(&libc::SYS_ptrace),
            "compat profile should keep ptrace available for higher-level policy decisions"
        );
        assert!(
            default_denied_syscalls().contains(&libc::SYS_ptrace),
            "default profile should still deny ptrace"
        );
        assert!(
            strict_denied_syscalls().contains(&libc::SYS_ptrace),
            "strict profile should still deny ptrace"
        );
    }

    #[test]
    fn strict_filter_blocks_socket_creation() {
        let status = run_in_child(|| {
            install(SeccompProfile::Strict).expect("strict seccomp should install");

            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd != -1 {
                return 1;
            }

            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                return 2;
            }

            0
        });

        assert_eq!(status, 0, "strict filter should block socket creation");
    }

    fn ptrace_traceme() -> libc::c_long {
        unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                0,
            )
        }
    }

    fn run_in_child(f: impl FnOnce() -> i32) -> i32 {
        let pid = unsafe { libc::fork() };
        assert_ne!(pid, -1, "fork should succeed");

        if pid == 0 {
            let code = f();
            unsafe { libc::_exit(code) }
        }

        let mut status = 0;
        let wait_result = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(wait_result, pid, "waitpid should succeed");
        assert!(libc::WIFEXITED(status), "child should exit normally");
        libc::WEXITSTATUS(status)
    }
}
