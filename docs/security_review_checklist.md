# Sandbox Security Review Checklist

This checklist is the release gate for the Rust sandbox. It turns `T047` into a repeatable process instead of relying on memory before rollout.

## How To Use

- Run this checklist before the first production rollout of a new sandbox version.
- Run it again whenever namespace, cgroup, seccomp, mount, cleanup, or artifact handling logic changes.
- Treat any unchecked `must` item as a release blocker.
- Record evidence links, command outputs, and owner names in the release note or change request.

## Review Metadata

- Review date:
- Version / commit:
- Reviewer:
- Environment:
- Threat model changes since last review:

## 1. Manual Security Review

### Isolation Boundaries

- [ ] `must`: rootfs/chroot boundaries still prevent reading files outside the sandbox-visible tree.
- [ ] `must`: writable paths are limited to the intended work/output areas and do not expose host-controlled escape paths.
- [ ] `must`: `/proc` is only mounted when expected and does not reveal host processes or unexpected kernel details.
- [ ] `must`: network isolation still blocks outbound access in the intended profiles.
- [ ] `must`: IPC isolation still blocks communication with host or foreign workloads.
- [ ] `should`: readonly input mapping still prevents in-sandbox tampering of mounted inputs.

### Privilege Model

- [ ] `must`: payload processes run with user namespace isolation when the strict profile expects it.
- [ ] `must`: capability dropping still happens before payload code executes.
- [ ] `must`: `no_new_privs` remains enabled before seccomp or payload exec.
- [ ] `must`: writable mounts keep `nodev`, `nosuid`, and `noexec` where the design expects them.
- [ ] `should`: no newly added CLI/debug path bypasses the normal privilege-reduction flow.

### Syscall And Kernel Attack Surface

- [ ] `must`: seccomp profile defaults still match the documented threat model.
- [ ] `must`: high-risk syscalls such as `mount`, `unshare`, `ptrace`, and `bpf` are still denied or otherwise isolated by design.
- [ ] `must`: `strict` profile still prevents new network socket creation.
- [ ] `should`: any newly required syscall has a written compatibility reason before being allowed.
- [ ] `should`: the compatibility gap between `default`, `compat`, and `strict` stays documented.

### Resource Exhaustion And Containment

- [ ] `must`: cgroup limits are still applied before untrusted workloads can fork or allocate freely.
- [ ] `must`: timeout handling still terminates the full process tree rather than only the direct child.
- [ ] `must`: memory-limit and CPU-limit failures still map to user-visible result statuses.
- [ ] `should`: stress behavior under concurrent runs is still within the latest accepted baseline.

### Cleanup And Artifact Safety

- [ ] `must`: failure during setup, spawn, timeout, or wait still triggers cleanup of processes, cgroups, and mount artifacts.
- [ ] `must`: artifact directories do not leak sensitive host files, credentials, or unrelated runtime state.
- [ ] `must`: stdout/stderr capture paths remain inside the planned artifact root.
- [ ] `should`: repeated failed runs do not accumulate stale sandbox directories.

### Auditability And Operator Visibility

- [ ] `must`: `sandbox_audit` events still cover run start, setup milestones, termination reason, cleanup, and run finish.
- [ ] `must`: user-visible CLI error categories still distinguish config issues, capability issues, runtime failures, and cleanup failures.
- [ ] `should`: operators can correlate a failed run with its artifact directory, config, and audit trail without manual guesswork.

## 2. Pre-Launch Checks

### Required Commands

- [ ] `must`: `cargo fmt --all --check`
- [ ] `must`: `cargo check --workspace`
- [ ] `must`: `cargo test --workspace --exclude sandbox-seccomp --exclude sandbox-supervisor`
- [ ] `must`: `cargo test -p sandbox-supervisor -- --test-threads=1`
- [ ] `must`: `cargo test -p sandbox-seccomp -- --test-threads=1`
- [ ] `must`: `./scripts/run_regression_suite.sh`
- [ ] `should`: `./scripts/run_stress_suite.sh --iterations 12 --concurrency 4 --report docs/stress_test_report.md`

### Config And Runtime Validation

- [ ] `must`: `cargo run -p sandbox-cli -- validate --config configs/minimal.toml`
- [ ] `must`: `cargo run -p sandbox-cli -- validate --config configs/strict.toml`
- [ ] `must`: `cargo run -p sandbox-cli -- inspect --config configs/minimal.toml`
- [ ] `must`: `cargo run -p sandbox-cli -- inspect --config configs/strict.toml`
- [ ] `should`: `cargo run -p sandbox-cli -- debug --config configs/minimal.toml`
- [ ] `should`: `cargo run -p sandbox-cli -- debug --config configs/strict.toml`

### Security Scenario Sign-Off

- [ ] `must`: malicious samples in [malicious_sample_catalog.md](/home/anyu/projects/sandbox/docs/malicious_sample_catalog.md) still match the current threat model.
- [ ] `must`: host filesystem escape probes fail as expected.
- [ ] `must`: `/proc` information leak probes fail as expected.
- [ ] `must`: readonly input tamper attempts fail as expected.
- [ ] `must`: seccomp denial scenarios still fail with the expected profile behavior.
- [ ] `should`: open gaps listed in the catalog have an owner and target milestone.

### Host And Deployment Readiness

- [ ] `must`: target rollout hosts are Linux systems with the namespace features required by the chosen profile.
- [ ] `must`: target rollout hosts provide writable cgroup v2 support when resource limits are enabled.
- [ ] `must`: rollout documentation states whether `minimal` or `strict`-style settings are being used and why.
- [ ] `must`: on-call or operators know where artifacts and audit logs are stored.
- [ ] `should`: rollback steps are documented for the exact deployment path.

## 3. Release Decision

- Release status:
- Blocking issues:
- Accepted residual risks:
- Follow-up actions:

## 4. Evidence Links

- Regression run:
- Stress run:
- Audit log sample:
- Config used for sign-off:
- Related issue / PR:
