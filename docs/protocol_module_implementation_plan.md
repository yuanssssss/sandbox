# Protocol 模块实现计划

## 1. 目标

`sandbox-protocol` 当前只定义了 `ExecutionRequest`、`ExecutionReport` 等序列化结构。
为了真正支持服务端接入，这个模块需要升级为“协议模型 + HTTP transport”层，对外暴露稳定 API，
对内复用 `sandbox-supervisor` 现有执行链路，而不是在 CLI 中重复实现一套调度逻辑。

本计划以 `axum` 为 Web 框架，先交付同步执行版本的 API，后续再平滑扩展异步任务队列。

## 2. 设计原则

- 复用现有领域模型：继续使用 `ExecutionConfig`、`ExecutionResult`、`SandboxError`。
- 保持依赖方向清晰：`sandbox-protocol` 依赖 `sandbox-supervisor`，避免反向耦合。
- 先做可运行 MVP：优先覆盖健康检查、配置校验、能力探测、执行任务。
- 让 transport 可复用：协议 crate 输出 `axum::Router`，CLI 或独立服务都可以挂载。
- 为异步化预留空间：请求和响应中保留 `request_id`、`artifact_dir`、审计事件等上下文。

## 3. 推荐 crate 边界

- `sandbox-protocol`
  负责请求/响应模型、错误映射、`axum` 路由、后端 trait 抽象、默认 supervisor 适配。
- `sandbox-supervisor`
  继续负责真正的执行、namespace 能力探测、artifact 规划。
- `sandbox-cli`
  增加 `serve` 子命令，仅负责装配并启动 HTTP 服务。

这样可以避免把 Web 逻辑塞进 CLI，同时又不需要额外新建 server crate。

## 4. API MVP

### `GET /healthz`

用途：
返回服务健康状态，供进程探活和负载均衡使用。

响应建议：

```json
{
  "status": "ok",
  "service": "sandbox-protocol"
}
```

### `GET /api/v1/capabilities`

用途：
暴露主机 namespace 能力探测结果，帮助 orchestrator 在下发任务前判断宿主机能力。

响应建议：

```json
{
  "user_namespace": { "available": true, "reason": null },
  "mount_namespace": { "available": true, "reason": null },
  "pid_namespace": { "available": true, "reason": null },
  "network_namespace": { "available": false, "reason": "..." },
  "ipc_namespace": { "available": true, "reason": null }
}
```

### `POST /api/v1/config/validate`

用途：
只校验配置合法性，不执行 payload。

请求体：

```json
{
  "config": { "...": "ExecutionConfig" }
}
```

响应建议：

```json
{
  "valid": true,
  "resource_limits": {
    "wall_time_ms": 1000,
    "cpu_time_ms": 500,
    "memory_bytes": 268435456,
    "max_processes": 16
  }
}
```

### `POST /api/v1/executions`

用途：
同步执行一个任务并返回结果，是 MVP 的核心接口。

请求体建议：

```json
{
  "request_id": "run-001",
  "config": { "...": "ExecutionConfig" },
  "command_override": ["python3", "main.py"],
  "artifact_dir": "/tmp/sandbox-api/run-001"
}
```

响应建议：

```json
{
  "request": { "...": "ExecutionRequest" },
  "result": { "...": "ExecutionResult" },
  "audit_events": [
    { "stage": "accepted", "message": "execution request accepted" },
    { "stage": "completed", "message": "execution finished" }
  ]
}
```

### `POST /api/v1/judge-jobs`

用途：
定义面向评测流水线的多阶段协议模型，显式表达 `compile`、`run`、`checker`
三个阶段的输入、输出、状态和 artifact 边界。

当前兼容策略：

- 保留现有 `/api/v1/executions` 作为单次执行入口
- 新增 `/api/v1/judge-jobs` 作为多阶段协议入口
- run-only judge job 仍然可用，便于平滑迁移已有调用方
- 当前后端已经支持 `compile -> run -> checker` 顺序执行
- 任一阶段失败都会停止后续阶段，并把未执行阶段标成 `skipped`
- `stdin` artifact 引用会直接接到后续阶段输入，`readonly_artifacts` 会被物化到受控输入目录后再挂载
- 已支持通过 HTTP 查询 judge job artifact 索引并读取单个文件
- 当前 artifact 注册表仍是进程内内存缓存，重启服务后需要重新执行任务才能再次下载

请求体建议：

```json
{
  "request_id": "judge-run-001",
  "artifact_dir": "/tmp/sandbox-api/judge-run-001",
  "run": {
    "command_override": ["/bin/echo", "hello from judge job"],
    "config": { "...": "ExecutionConfig" }
  }
}
```

多阶段 schema 示例：

```json
{
  "request_id": "judge-pipeline-001",
  "artifact_dir": "/tmp/sandbox-api/judge-pipeline-001",
  "compile": {
    "artifact_dir": "/tmp/sandbox-api/judge-pipeline-001/compile",
    "config": { "...": "ExecutionConfig" }
  },
  "run": {
    "inputs": {
      "stdin": { "stage": "compile", "artifact_path": "outputs/program.txt" }
    },
    "config": { "...": "ExecutionConfig" }
  },
  "checker": {
    "inputs": {
      "stdin": { "stage": "run", "artifact_path": "stdout.log" }
    },
    "config": { "...": "ExecutionConfig" }
  }
}
```

响应建议：

```json
{
  "request": { "...": "JudgeJobRequest" },
  "status": "completed",
  "compile": {
    "stage": "compile",
    "status": "completed",
    "artifact_dir": "/tmp/sandbox-api/judge-pipeline-001/compile",
    "compilation_result": { "...": "CompilationResult" }
  },
  "run": {
    "stage": "run",
    "status": "completed",
    "artifact_dir": "/tmp/sandbox-api/judge-pipeline-001/run",
    "result": { "...": "ExecutionResult" },
    "artifacts": [
      { "name": "stdout", "kind": "stdout", "path": "/tmp/.../stdout.log" },
      { "name": "stderr", "kind": "stderr", "path": "/tmp/.../stderr.log" }
    ]
  },
  "checker": {
    "stage": "checker",
    "status": "completed",
    "artifact_dir": "/tmp/sandbox-api/judge-pipeline-001/checker",
    "result": { "...": "ExecutionResult" }
  }
}
```

### `GET /api/v1/judge-jobs/{request_id}/artifacts`

用途：
返回该 judge job 各阶段当前可见的 artifact 索引，至少覆盖 `stdout`、`stderr`
以及 `outputs/` 目录下的文件。

响应建议：

```json
{
  "request_id": "judge-pipeline-001",
  "stages": [
    {
      "stage": "compile",
      "status": "completed",
      "artifact_dir": "/tmp/sandbox-api/judge-pipeline-001/compile",
      "artifacts": [
        { "path": "stdout.log", "kind": "stdout", "size_bytes": 32 },
        { "path": "stderr.log", "kind": "stderr", "size_bytes": 0 },
        { "path": "outputs/program.txt", "kind": "file", "size_bytes": 15 }
      ]
    }
  ]
}
```

### `GET /api/v1/judge-jobs/{request_id}/artifacts/{stage}/file?path=...`

用途：
读取某个阶段 artifact 根目录下的单个文件内容，例如：

- `stdout.log`
- `stderr.log`
- `outputs/program.txt`

约束：

- `path` 必须是相对路径
- 不允许 `..`、绝对路径或根路径逃逸
- 当前只暴露阶段显式产物和 `outputs/` 目录中的文件，不暴露内部 `rootfs/`、`work/`、
  `stage-inputs/` 等实现细节目录

## 5. 错误映射

协议层需要把 `SandboxError` 映射成稳定的 HTTP 语义：

- `Config` -> `400 Bad Request`
- `CapabilityUnavailable` -> `409 Conflict`
- `Permission` -> `403 Forbidden`
- `UnsupportedPlatform` -> `501 Not Implemented`
- `Timeout` -> `408 Request Timeout`
- `Io` / `Spawn` / `Cleanup` / `Internal` -> `500 Internal Server Error`

统一错误响应建议：

```json
{
  "error": {
    "code": "configuration",
    "message": "configuration error: ...",
    "request_id": "run-001"
  }
}
```

## 6. 模块拆分建议

`sandbox-protocol/src/lib.rs` 可以拆成以下逻辑区块：

- 协议模型：请求、响应、错误对象、能力探测对象
- 后端抽象：`ProtocolBackend` trait
- 默认实现：`SupervisorBackend`
- `axum` 路由构建：`build_router`
- handler：`healthz`、`capabilities`、`validate_config`、`execute`

如果后续继续扩展，可以再拆成 `types.rs`、`server.rs`、`backend.rs`。

## 7. 落地顺序

1. 给 workspace 增加 `axum`、`tokio` 依赖。
2. 在 `sandbox-protocol` 中实现协议模型和 `axum` 路由。
3. 用 `ProtocolBackend` trait 封装执行与能力探测。
4. 用 `SupervisorBackend` 复用 `sandbox-supervisor::run`。
5. 在 `sandbox-cli` 中增加 `serve` 子命令并启动 `axum` 服务。
6. 为路由补单元测试，覆盖成功路径和错误映射。

## 8. 下一阶段扩展

MVP、多阶段协议模型、基础阶段编排和 artifact 读取接口完成后，建议按下面顺序继续扩展：

1. 增加异步任务模型到 `judge-jobs`，返回 `202 Accepted` 与任务 ID。
2. 给内存中的 artifact 注册表补 TTL、容量上限和清理策略。
3. 增加审计日志流式输出或 SSE。
4. 增加鉴权、中间件、请求大小限制和并发限制。

补充说明：

- 现有 `/api/v1/executions/async` 已补基础保留策略：默认只保留最近 1024 条任务，
  完成/失败后默认保留 5 分钟，过期任务会在后续提交或查询时被清理
- 现有 `/api/v1/executions/{task_id}/events` 已补 SSE 事件流：会先回放已有事件，再继续输出
  `accepted`、`running`、`completed`、`failed`，终态后断流
- 现有 `/api/v1/judge-jobs/async` 与 `/api/v1/judge-jobs/tasks/{task_id}` 已补基础异步任务模型，
  并复用和 execution async 相同的默认保留策略
- 现有 judge job artifact 注册表已补基础缓存策略：默认保留 5 分钟，最多缓存 1024 条，
  达到上限时淘汰最老的一条缓存结果
- 现有 `/api/v1/judge-jobs/tasks/{task_id}/events` 已补 SSE 事件流：会回放 `task_status` 与
  `stage` 事件，并在终态后断流
- 现有 execution / judge job SSE 已统一成共享事件模型：客户端可按 `task_kind` 和
  `event_type` 解析，不需要维护两套事件结构
- 现有服务入口已补基础保护层：支持 Bearer 鉴权、默认 `1 MiB` 请求体限制和默认 32 并发上限；
  `GET /healthz` 仍保持免鉴权
- 现有 `sandbox-cli serve` 已支持 `--server-config`，可从 TOML 持久化读取鉴权与限制参数，
  并允许 CLI 参数覆盖配置文件中的值
- 现有鉴权已支持细粒度 read/write token：GET/HEAD 接受 read 或 write token，POST 要求 write token

## 9. 当前实现结论

当前仓库最适合的方案不是单独新建一个 web 服务工程，而是先把 `sandbox-protocol`
升级成可复用的 HTTP transport 库，并由 `sandbox-cli serve` 承载运行入口。
这样改动最小、复用度最高，也最符合现有 workspace 的演进方式。
