# Rust Sandbox Scaffold

这个仓库现在已经按设计文档搭好了第一阶段脚手架，并打通了一条最小可运行执行链路。

## 当前覆盖

- `M0` 项目脚手架与基础设施
- `M1` 最小执行器的核心路径

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
  - 为后续 `mount namespace` 和 `pivot_root/chroot` 接入保留生命周期入口
  - 已接入默认关闭的 `enter_mount_namespace` / `apply_mounts` / `chroot_to_rootfs` 开关
  - 已支持把可执行目录单独绑定进 rootfs，例如 `/bin`、`/usr/bin`
  - 已补环境能力探测，在不支持 namespace 的环境里会给出明确错误
  - 已接入默认关闭的 `user namespace` 开关，并在执行前完成 `no_new_privs`、bounding set 与 capability sets 降权
  - 已接入 `PID namespace` 流程，并把 `/proc` 的挂载时机延后到新的 pid 视图中
  - 已接入默认关闭的 `network namespace` / `IPC namespace` 开关与能力探测
  - 已接入 `security.seccomp_profile = "default"` 的最小 seccomp 黑名单过滤器，并为 `strict/compat` profile 预留安装入口

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

其中 `sandbox-cgroup`、`sandbox-mount`、`sandbox-seccomp`、`sandbox-testkit` 目前先提供了明确的模块占位和后续演进方向，便于下一阶段继续实现 `M2-M6`。
其中 `sandbox-mount` 现在已经可以准备最小 rootfs scaffold，但还没有真正执行 `mount(2)` 和切根。

## 使用方式

校验配置：

```bash
cargo run -p sandbox-cli -- validate --config configs/minimal.toml
```

执行示例配置：

```bash
cargo run -p sandbox-cli -- run --config configs/minimal.toml
```

覆盖命令：

```bash
cargo run -p sandbox-cli -- run --config configs/minimal.toml --command /bin/echo override
```

## 下一步建议

优先继续做这些任务：

1. `sandbox-mount` 中实现最小 rootfs、`tmpfs`、`bind mount`
2. `sandbox-supervisor` 中接入 `unshare/clone` 与 PID/network/IPC namespace
3. `sandbox-cgroup` 中实现 cgroup v2 路径管理与资源统计
4. 再把统计结果回填到 `ExecutionResult`

## 验证

```bash
cargo fmt --all
cargo check
cargo test
```
