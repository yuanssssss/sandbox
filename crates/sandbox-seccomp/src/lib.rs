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
        SeccompProfile::Strict => Err(SeccompError::UnimplementedProfile("strict")),
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
    default_denied_syscalls()
}

pub fn roadmap() -> &'static str {
    "M4 scaffold: model seccomp profiles and install syscall filters as defense in depth."
}
