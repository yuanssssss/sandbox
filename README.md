# Rust Sandbox Scaffold

这个仓库现在已经按设计文档搭好了从最小执行链路到基础安全隔离、资源限制的一条可运行主线。

## 当前覆盖

- `M0` 项目脚手架与基础设施
- `M1` 最小执行器的核心路径
- `M2` rootfs 与 namespace 骨架
- `M3` cgroup v2 资源限制基础接线
- `M4` capability drop 与 seccomp 第一版

已完成能力：

- Rust workspace 与 crate 边界
- 统一错误类型与执行结果模型
- TOML 配置解析与校验
- `tracing` 日志初始化
- CLI 入口：`run` / `validate`
- 最小 supervisor：
  - 启动子进程
  - 输出重定向到产物目录
  - wall-clock 超时
  - 按进程组发送 `SIGTERM` / `SIGKILL` 回收
- `M2` rootfs scaffold：
  - 在产物目录下准备最小 rootfs 目录结构
  - 生成只读运行库、`/work`、`/tmp`、`/proc` 的挂载计划
  - 已接入默认关闭的 `enter_mount_namespace` / `apply_mounts` / `chroot_to_rootfs` 开关
  - 已支持把可执行目录单独绑定进 rootfs，例如 `/bin`、`/usr/bin`
  - 已补环境能力探测，在不支持 namespace 的环境里会给出明确错误
  - 已接入默认关闭的 `user namespace` 开关，并在执行前完成 `no_new_privs`、bounding set 与 capability sets 降权
  - 已接入 `PID namespace` 流程，并把 `/proc` 的挂载时机延后到新的 pid 视图中
  - 已接入默认关闭的 `network namespace` / `IPC namespace` 开关与能力探测
  - 已接入 `security.seccomp_profile` 的真实过滤器：`default`、`compat`、`strict`
- `M3` cgroup v2：
  - 已实现 cgroup v2 root 探测、scope 路径规划、目录创建与清理
  - 已接入 `memory.max`、`memory.swap.max`、`pids.max`，以及基于 `cpu.stat` 轮询的 CPU time limit
  - 已在 supervisor 中接入 cgroup 创建、PID attach、usage 读取与清理
  - 已把 `cpu.stat` / `memory.peak` 等结果回填到 `ExecutionResult.usage`
  - 已把 `cpu_time_ms` 超限映射为 `TimeLimitExceeded`
  - 已把 `memory.events` / `memory.events.local` 中的 OOM 信号映射为 `MemoryLimitExceeded`
- `M4` seccomp：
  - `default` profile 会拦截高风险 syscall，例如 `mount`、`unshare`、`ptrace`、`bpf`
  - `compat` profile 比 `default` 更宽松，保留 `ptrace`
  - `strict` profile 在 `default` 基础上进一步阻止网络 socket 创建
  - 已补 `sh` / `python3` 在 `default`、`compat`、`strict` 下的兼容性回归，避免误伤常见运行时
  - 已支持把宿主机输入以 `filesystem.readonly_bind_paths` 只读挂到沙箱内的 `/inputs/<basename>`，并把 `filesystem.output_dir` 映射到 artifact 下的受控可写目录
- `M5` 审计日志：
  - 已通过 `tracing` 输出 `sandbox_audit` 结构化事件，覆盖 `run_start`、`rootfs_prepared`、`cgroup_prepared`、`payload_spawned`、`termination_reason`、`cgroup_finalized`、`run_finished`
  - 已加固异常清理路径：setup/spawn/wait 异常后会清理 cgroup，并终止已启动的 payload 进程组
  - CLI 已补用户可见错误报告：可区分配置问题、能力缺失、I/O/setup 失败与 payload 运行失败，并给出建议排查方向

## Workspace 结构

```text
crates/
├─ sandbox-core
├─ sandbox-config
├─ sandbox-protocol
├─ sandbox-supervisor
├─ sandbox-cli
├─ sandbox-cgroup
├─ sandbox-mount
├─ sandbox-seccomp
└─ sandbox-testkit
```

其中 `sandbox-mount`、`sandbox-cgroup`、`sandbox-seccomp` 已经接入了第一版真实能力；`sandbox-testkit` 主要承载场景脚本与回归用例。

## 使用方式

校验配置：

```bash
cargo run -p sandbox-cli -- validate --config configs/minimal.toml
```

执行示例配置：

```bash
cargo run -p sandbox-cli -- run --config configs/minimal.toml
```

当前 `configs/minimal.toml` 默认保持“尽量容易在普通开发环境跑通”的配置：

- 默认启用 `security.seccomp_profile = "default"`
- 默认不启用 mount / pid / network / ipc / user namespace
- 默认不启用 cgroup 限额写入，`cpu_time_ms` / `memory_bytes` / `max_processes` 需要按需打开

如果你要开启更强隔离：

- 设置 `limits.cpu_time_ms`、`limits.memory_bytes` 或 `limits.max_processes` 会启用 cgroup v2，要求宿主机提供可写 cgroup v2
- 设置 `filesystem.enter_user_namespace` / `enter_mount_namespace` / `enter_pid_namespace` 等开关时，要求宿主机支持对应 namespace

一个更强的配置通常至少会包含：

```toml
[limits]
memory_bytes = 134217728
max_processes = 32

[security]
seccomp_profile = "default"

[filesystem]
enter_user_namespace = true
enter_mount_namespace = true
enter_pid_namespace = true
apply_mounts = true
chroot_to_rootfs = true
mount_proc = true
```

覆盖命令：

```bash
cargo run -p sandbox-cli -- run --config configs/minimal.toml --command /bin/echo override
```

## 下一步建议

优先继续做这些任务：

1. 把 cgroup v2 的 CPU 控制与更完整统计接上
2. 继续扩 seccomp profile 与 deny-list 覆盖
3. 继续做 mount / cgroup / 子进程失败路径的清理加固
4. 补审计日志和更细的用户可见错误报告

## 验证

```bash
cargo fmt --all
cargo check
cargo test
```
