# Next Steps

## 背景

当前仓库的基础沙箱能力、协议 MVP、异步执行查询、Docker 开发环境和示例工程已经具备。
下一阶段的重点不再是补齐基础功能，而是把系统从“单次沙箱执行器”推进到“可支撑评测流水线的服务”。

结合 [rust_sandbox_task_breakdown.md](/home/anyu/projects/sandbox/docs/rust_sandbox_task_breakdown.md)、
[protocol_module_implementation_plan.md](/home/anyu/projects/sandbox/docs/protocol_module_implementation_plan.md)、
[malicious_sample_catalog.md](/home/anyu/projects/sandbox/docs/malicious_sample_catalog.md) 和当前实现状态，
推荐优先推进下面这些事项。

## 当前进度

- [x] 已完成第 1 项：协议层已新增 `JudgeJobRequest` / `JudgeJobReport` 与 `/api/v1/judge-jobs`
  路由，现有 `/api/v1/executions` 保持兼容
- [x] 已完成第 2 项：supervisor / CLI 已新增独立 `compile` 执行模型，可区分
  `compilation_failed` 与沙箱失败，并返回编译产物路径
- [x] 已完成第 3 项：judge job 已支持 `compile -> run -> checker` 阶段编排，
  任一阶段失败都会短路后续阶段，并返回逐阶段报告
- [x] 已完成第 4 项：protocol 已支持 judge job artifact 索引和文件读取接口，可通过
  HTTP 读取各阶段 `stdout`、`stderr` 和 `outputs/` 下的文件
- [x] 已完成第 5 项：已补 Unix domain socket 与 checker 混跑风险样例，并验证
  错误混跑会暴露 secret、正确分层时只能得到 `no_socket`
- [x] 已完成第 6 项：`examples/01` 已升级成多阶段评测 demo，补齐了 C++ / Java / Python
  的 compile/run/checker 请求模板、Makefile target 和文档
- [x] 已完成第 7 项：异步执行任务已补默认保留期、最大任务数和过期清理策略，
  完成/失败任务默认保留 5 分钟，最多保留 1024 条
- [x] 已完成第 8 项：`/api/v1/executions/{task_id}/events` 已支持 SSE 事件流，
  会回放已有状态事件并在终态后自动断流
- [x] 已完成后续扩展：`judge-jobs` 已支持异步提交与任务状态查询，
  完成后仍可继续按 `request_id` 读取 artifacts
- [x] 已完成后续扩展：judge job artifact 注册表已补默认保留期、容量上限和淘汰策略，
  默认保留 5 分钟，最多保留 1024 条，超限时淘汰最老缓存
- [x] 已完成后续扩展：`/api/v1/judge-jobs/tasks/{task_id}/events` 已支持 SSE，
  会回放 task_status / stage 事件并在终态后断流
- [x] 已完成后续扩展：协议服务已补 Bearer 鉴权、请求体大小限制和并发限制，
  `healthz` 默认保持免鉴权
- [x] 已完成后续扩展：`sandbox-cli serve` 已支持 `--server-config`，可持久化保存鉴权和限制参数
- [x] 已完成后续扩展：execution / judge job SSE 已统一成共享事件模型，
  客户端可按 `task_kind + event_type` 统一消费
- [ ] 当前下一步：如果继续工程化，可优先补细粒度权限

## 推荐顺序

1. 定义多阶段评测协议模型
2. 实现编译阶段执行模型
3. 实现 checker 分层与阶段编排
4. 增加 artifact 索引和下载接口
5. 补 Unix domain socket 与 checker 混跑攻击样例
6. 补编译阶段隔离样例与文档
7. 增加异步任务的保留期与清理机制
8. 增加协议层流式状态输出

## 事项列表

### 1. 定义多阶段评测协议模型

范围：
把现在 `crates/sandbox-protocol/src/lib.rs` 里的单次 `ExecutionRequest` / `ExecutionReport`
扩成 `JudgeJobRequest` / `JudgeJobReport`，明确 `compile`、`run`、`checker`
三个阶段的输入、输出、状态和 artifact。

涉及：
- `crates/sandbox-protocol/src/lib.rs`
- `docs/protocol_module_implementation_plan.md`
- `protocol.http`

验收：
- 协议层能表达三阶段任务
- JSON schema 清晰
- 现有单次执行接口不被误删，或有明确兼容策略

### 2. 实现编译阶段执行模型

范围：
先把“编译”从普通执行里独立出来，支持编译命令、源码目录、编译产物目录、
编译 `stdout/stderr`、编译失败状态。

涉及：
- `crates/sandbox-supervisor/src/lib.rs`
- `crates/sandbox-cli/src/main.rs`
- `examples/01`

验收：
- 能提交一个 C/C++ 编译任务
- 成功时拿到二进制产物路径
- 失败时能区分“编译失败”和“沙箱失败”

### 3. 实现 checker 分层与阶段编排

范围：
在后端执行链路里串起来 `compile -> run -> checker`，checker 只读取受控输入和
run 阶段产物，不和用户程序混在同一进程或同一阶段。

涉及：
- `crates/sandbox-protocol/src/lib.rs`
- `crates/sandbox-supervisor/src/lib.rs`

验收：
- 一个完整评测任务可以按阶段执行
- 任一阶段失败都会停止后续阶段
- 最终报告里有每个阶段独立结果

### 4. 增加 artifact 索引和下载接口

范围：
给 protocol 增加结果产物读取能力，至少支持查看阶段 artifact 列表、读取 `stdout`、
读取 `stderr`、读取受控输出目录中的文件。

涉及：
- `crates/sandbox-protocol/src/lib.rs`
- `protocol.http`

验收：
- 能通过 HTTP 拿到 `compile/run/checker` 各阶段 `stdout/stderr`
- 路径不会逃逸 artifact 根目录
- 错误响应统一

### 5. 补 Unix domain socket 与 checker 混跑攻击样例

范围：
落实 `docs/malicious_sample_catalog.md` 里还没补的 UDS / checker 风险样例，
验证分层设计不是纸面上的。

涉及：
- `crates/sandbox-testkit`
- `crates/sandbox-supervisor/src/lib.rs`
- `docs/malicious_sample_catalog.md`

验收：
- 新增样例能稳定复现
- 错误的混跑方式会暴露风险
- 正确的分层方式能通过回归

### 6. 补编译阶段隔离样例与文档

范围：
增加 C/C++、Java、Python 的 `compile/run/checker` 示例配置和文档，把现在
`examples/01` 从“单程序 demo”升级成“多阶段评测 demo”。

涉及：
- `examples/01`
- `README.md`
- `protocol.http`

验收：
- 用户能按文档走通至少一条完整评测链路
- 协议请求样例可直接复用

### 7. 增加异步任务的保留期与清理机制

范围：
现在 async task 只存在内存 `HashMap` 里，先补 TTL、最大任务数、完成后清理策略，
避免服务长期运行后内存膨胀。

涉及：
- `crates/sandbox-protocol/src/lib.rs`

验收：
- 任务过期会被清理
- 超出上限时有明确错误
- 不会影响正在运行的任务

### 8. 增加协议层流式状态输出

范围：
给 async task 增加 SSE 或简化版事件流，输出 `accepted`、`running`、`completed`、
`failed` 以及阶段切换事件。

涉及：
- `crates/sandbox-protocol/src/lib.rs`
- `protocol.http`

验收：
- 客户端不用轮询也能看到任务推进
- 断流时行为明确
- 至少有基础测试覆盖
