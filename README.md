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
- 统一错误类型、运行结果模型与编译结果模型
- TOML 配置解析与校验
- `tracing` 日志初始化
- CLI 入口：`compile` / `run` / `validate` / `inspect` / `debug` / `serve`
- 最小 supervisor：
  - 启动子进程
  - 输出重定向到产物目录
  - wall-clock 超时
  - 按进程组发送 `SIGTERM` / `SIGKILL` 回收
- `sandbox-protocol` HTTP transport：
  - 已暴露 `GET /healthz`、`GET /api/v1/capabilities`
  - 已暴露 `POST /api/v1/config/validate` 与同步执行接口 `POST /api/v1/executions`
  - 已补兼容现有同步接口的异步执行接口 `POST /api/v1/executions/async`
  - 已补 `GET /api/v1/executions/{task_id}` 任务状态查询
  - 已统一协议层错误响应，包括配置错误、JSON 解析错误、`404`、`405`
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
  - 已补 `configs/minimal.toml` 与 `configs/strict.toml` 两套模板，分别覆盖“尽量易跑通”和“尽量强隔离”两类本地调试场景
  - 已补 `inspect` / `debug` 调试命令，可直接查看派生的 artifact/rootfs/cgroup 路径、namespace 可用性与执行结果
- `M6` 安全验证：
  - 已在 `sandbox-testkit` 中补恶意样例与压力场景 catalog，见 `docs/malicious_sample_catalog.md`
  - 已补本地回归脚本 `scripts/run_regression_suite.sh` 与 GitHub Actions `regression.yml`
  - 已补压力脚本 `scripts/run_stress_suite.sh`、工作流 `stress.yml`，并生成基线报告 `docs/stress_test_report.md`
  - 已补上线前安全评审清单 `docs/security_review_checklist.md`，覆盖人工审查项、发布前命令检查与上线证据留档

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
cargo run -p sandbox-cli -- validate --config configs/strict.toml
```

执行编译任务：

```bash
cargo run -p sandbox-cli -- compile \
  --config examples/01/configs/compile.toml \
  --source-dir . \
  --output-dir examples/01/build
```

执行示例配置：

```bash
cargo run -p sandbox-cli -- run --config configs/minimal.toml
cargo run -p sandbox-cli -- run --config configs/strict.toml
```

查看派生调试信息：

```bash
cargo run -p sandbox-cli -- inspect --config configs/minimal.toml
cargo run -p sandbox-cli -- inspect --config configs/strict.toml
```

带调试上下文执行：

```bash
cargo run -p sandbox-cli -- debug --config configs/minimal.toml
```

启动 HTTP API：

```bash
cargo run -p sandbox-cli -- serve --listen 127.0.0.1:3000
```

## Docker 环境

仓库根目录现在提供了两套容器环境：

- 开发环境镜像：`docker/dev.Dockerfile`
  - 适合在容器里改代码、编译、跑测试
  - 内置 Rust 工具链，以及 C/C++、Java、Python 的编译和运行依赖
- 发布环境镜像：`docker/prod.Dockerfile`
  - 多阶段构建，最终镜像默认启动 `sandbox-cli serve --listen 0.0.0.0:3000`
  - 同样包含 C/C++、Java、Python 的编译和运行依赖，便于在容器内执行多语言 payload

根目录 `Makefile` 提供了常用命令：

```bash
make docker-build-dev
make docker-shell-dev
make docker-build-prod
make docker-run-prod
make docker-shell-prod
```

其中：

- `docker-shell-dev` 会自动创建或启动开发容器，并把当前仓库挂到 `/workspace`
- `docker-run-prod` 会启动发布容器并映射 `3000` 端口
- 由于这个项目依赖 namespace、cgroup 和 seccomp，容器运行参数里默认包含 `--privileged` 和 `/sys/fs/cgroup` 挂载

运行本地回归：

```bash
./scripts/run_regression_suite.sh
```

生成压力报告：

```bash
./scripts/run_stress_suite.sh --iterations 12 --concurrency 4 --report docs/stress_test_report.md
```

其中：

- `compile` 用独立的编译结果模型返回 `source_dir`、`output_dir`、`outputs`，并区分 `compilation_failed` 与沙箱失败
- `validate` 只检查配置并打印摘要
- `inspect` 不执行 payload，只展示 artifact、rootfs、cgroup、readonly input 映射和 namespace 可用性
- `debug` 会先打印 `inspect` 信息，再实际执行 payload，适合定位 mount/cgroup/setup 失败
- `serve` 启动 `sandbox-protocol` 的 HTTP 服务，默认监听 `127.0.0.1:3000`

## HTTP API

启动服务后，可使用下面这些接口：

- `GET /healthz`
- `GET /api/v1/capabilities`
- `POST /api/v1/config/validate`
- `POST /api/v1/executions`
- `POST /api/v1/executions/async`
- `GET /api/v1/executions/{task_id}`

同步执行示例：

```bash
curl -sS http://127.0.0.1:3000/api/v1/executions \
  -H 'content-type: application/json' \
  -d '{
    "request_id": "run-001",
    "config": {
      "process": {
        "argv": ["/bin/echo", "hello"]
      },
      "limits": {
        "wall_time_ms": 1000
      },
      "filesystem": {
        "enable_rootfs": false
      }
    }
  }'
```

异步执行示例：

```bash
curl -sS http://127.0.0.1:3000/api/v1/executions/async \
  -H 'content-type: application/json' \
  -d '{
    "request_id": "run-async-001",
    "config": {
      "process": {
        "argv": ["/bin/echo", "hello"]
      },
      "limits": {
        "wall_time_ms": 1000
      },
      "filesystem": {
        "enable_rootfs": false
      }
    }
  }'
```

返回 `task_id` 后查询状态：

```bash
curl -sS http://127.0.0.1:3000/api/v1/executions/exec-1
```

错误响应统一为：

```json
{
  "error": {
    "code": "configuration",
    "message": "configuration error: ...",
    "request_id": "run-001"
  }
}
```

当前仓库提供两套模板：

- `configs/minimal.toml`
  - 默认启用 `security.seccomp_profile = "default"`
  - 默认不启用 mount / pid / network / ipc / user namespace
  - 默认不启用 cgroup 限额写入，适合先验证最小执行链路
- `configs/strict.toml`
  - 默认启用 `security.seccomp_profile = "strict"`
  - 默认启用 user / mount / pid / network / ipc namespace、`chroot`、`mount_proc`
  - 默认启用 `cpu_time_ms`、`memory_bytes`、`max_processes`
  - 适合在支持 namespace 和可写 cgroup v2 的 Linux 环境里验证更强隔离

使用 `strict.toml` 前需要确认：

- 设置 `limits.cpu_time_ms`、`limits.memory_bytes` 或 `limits.max_processes` 会启用 cgroup v2，要求宿主机提供可写 cgroup v2
- 设置 `filesystem.enter_user_namespace` / `enter_mount_namespace` / `enter_pid_namespace` 等开关时，要求宿主机支持对应 namespace

覆盖命令：

```bash
cargo run -p sandbox-cli -- run --config configs/minimal.toml --command /bin/echo override
```

## 下一步建议

优先继续做这些任务：

1. 继续补编译阶段、checker 分层和 Unix domain socket 相关攻击样例
2. 继续扩真实 cgroup v2 / namespace 特权环境下的压力基线
3. 视威胁模型再补更细的 seccomp 与 LSM/微虚拟机路线

## 验证

```bash
cargo fmt --all
cargo check
cargo test
```
