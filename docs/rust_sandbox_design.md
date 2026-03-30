# Rust 沙箱设计方案

## 1. 目标

本文给出一个面向评测系统或通用不可信程序执行场景的可行沙箱设计方案。  
设计目标参考了 `isolate` 的思路，并结合当前 Linux 生态进行增强。

核心目标：

- 安全执行不可信程序
- 对 CPU、内存、进程数、磁盘使用量进行限制
- 禁止网络访问和跨进程干扰
- 支持多进程、多线程程序
- 具备较低运行开销
- 便于用 Rust 实现、测试和维护

默认假设：

- 运行平台为现代 Linux
- 项目主要服务于评测系统、代码执行服务或自动化任务隔离
- 不追求完全对抗国家级攻击者，但要求能抵御常见逃逸、资源滥用和误配置风险

## 2. 威胁模型

沙箱需要防御的主要风险包括：

- 读取宿主机敏感文件
- 修改宿主机文件或系统状态
- 访问网络
- 与宿主机其他进程通信
- 杀死或干扰宿主机其他进程
- 通过 fork bomb、死循环、爆内存、爆磁盘实施 DoS
- 借助额外二进制、解释器或系统工具作弊
- 借助 `/proc`、环境变量、启动参数等泄漏内部信息

不完全覆盖的风险：

- 微架构侧信道
- 内核 0day
- 硬件级攻击
- 供应链污染的编译器或基础镜像

## 3. 总体设计思路

整体设计采用分层防御：

1. 用 `namespaces` 限制进程所能看到的系统资源
2. 用 `cgroup v2` 限制和统计整个进程组的资源占用
3. 用最小化 rootfs 和挂载策略减少文件系统暴露面
4. 用 `seccomp-bpf` 作为第二道防线限制高风险 syscall
5. 用独立 UID/GID、能力裁剪和最小特权原则降低管理器风险
6. 用 supervisor 进程负责生命周期管理、超时处理和审计日志

这套方案的核心不是“完全依赖 syscall allowlist”，而是：

- 先让危险对象不可见
- 再让危险 syscall 不可用
- 最后对资源和生命周期做强约束

## 4. 技术选型

### 4.1 操作系统能力

建议使用以下 Linux 特性：

- `PID namespace`
- `mount namespace`
- `network namespace`
- `IPC namespace`
- `UTS namespace`
- `user namespace`
- `cgroup v2`
- `seccomp-bpf`
- `rlimit`
- `pidfd`
- `tmpfs`
- `bind mount`
- `pivot_root` 或 `chroot`  
  优先 `pivot_root`，在实现受限时可退而求其次

### 4.2 关键安全策略

建议默认启用：

- rootfs 只读
- 工作目录单独挂载为可写
- 工作目录挂载 `nodev,nosuid,noexec`
- 禁止网络设备
- 使用独立 UID/GID
- 丢弃不必要 capabilities
- 通过 `seccomp` 禁掉高风险 syscall
- 使用 `cgroup v2` 限制内存、CPU、进程数
- 同时使用 CPU 时间和 wall-clock 时间限制

### 4.3 为什么选这些技术

`namespaces` 负责“隔离可见世界”，这是主隔离层。  
`cgroup v2` 负责“按整个沙箱计量资源”，防止多进程逃逸资源限制。  
`seccomp` 负责“细粒度禁止危险调用”，作为 defense-in-depth。  
`user namespace + capability drop` 负责降低启动后权限面。  
`pidfd` 负责更可靠地管理和回收子进程。  

## 5. 进程模型

建议采用三层进程结构：

### 5.1 Orchestrator

职责：

- 接收外部执行请求
- 生成任务目录与配置
- 调用 sandbox supervisor
- 汇总运行结果、日志和资源统计

特点：

- 不直接进入隔离环境
- 不持有长期高权限
- 可以是服务进程，也可以是 CLI

### 5.2 Sandbox Supervisor

职责：

- 创建 namespaces
- 设置 UID/GID、挂载、rootfs、环境变量
- 创建并配置 cgroup
- 安装 seccomp 规则
- 启动目标程序
- 监控超时、内存、退出状态
- 清理进程树、挂载点和 cgroup

特点：

- 是安全边界中的关键组件
- 代码必须小而可审计
- 尽量缩短持有特权的时间窗口

### 5.3 Sandbox Payload

职责：

- 执行不可信程序
- 只看到受限环境
- 所有资源消耗都记入对应 cgroup

## 6. 生命周期设计

一次执行任务的推荐流程如下：

1. Orchestrator 创建任务目录
2. 准备只读 rootfs 和任务工作目录
3. Supervisor 创建 cgroup 并写入资源限制
4. Supervisor 创建新的 user/mount/pid/ipc/net namespace
5. 配置挂载点、切换根目录、设置工作目录
6. 设置 rlimit、环境变量、stdin/stdout/stderr
7. 丢弃 capabilities，安装 seccomp 规则
8. 启动目标程序
9. 通过 `pidfd`、wait、计时器和 cgroup 文件监控运行状态
10. 到达限制或程序退出后，统一终止进程树
11. 回收挂载点、删除 cgroup、输出结果

## 7. 文件系统设计

### 7.1 rootfs 结构

建议采用“最小只读根 + 单独工作目录”的方式：

- `/lib`, `/lib64`, `/usr/lib`  
  只读绑定宿主机必要运行库，或预构建独立运行时目录

- `/bin`, `/usr/bin`  
  默认不暴露；若必须暴露，仅放极少数允许执行的程序

- `/tmp`  
  使用 `tmpfs`

- `/work`  
  任务专属工作目录，可写

### 7.2 文件系统策略

建议：

- 只暴露必需动态库和运行时文件
- 默认不暴露宿主机工具链
- 输入文件只读挂载
- 输出文件写入 `/work`
- 所有可写目录默认 `nodev,nosuid,noexec`
- 如需允许用户程序自身二进制执行，可将可执行文件放在单独允许执行的只读目录

### 7.3 `/proc` 和 `/sys`

建议：

- 只在确有需要时挂载最小 proc
- 不暴露 `/sys`
- 避免把宿主机设备节点带入 rootfs

## 8. 资源限制设计

### 8.1 CPU

建议结合两种机制：

- `cpu.max` 或相关 cgroup v2 CPU 控制接口
- wall-clock 超时

可选增强：

- `cpuset` 绑定固定 CPU 核
- 减少测时噪声
- 限制并行程序获得额外不公平优势

### 8.2 内存

使用 `cgroup v2 memory.max` 作为主限制。  
必要时同时设置：

- `memory.swap.max = 0`
- `memory.high`

这样可以避免程序借 swap 拖慢整机。

### 8.3 进程数

建议使用：

- `pids.max`

它比仅靠 `setrlimit` 更适合限制整个沙箱进程组。

### 8.4 文件大小与磁盘使用

建议同时做：

- `RLIMIT_FSIZE`
- 工作目录所在文件系统配额，或使用受控大小的单独挂载卷

如果项目早期不做真正磁盘配额，至少要：

- 将工作目录放在单独挂载点
- 做总空间巡检
- 在超限时强制终止

## 9. seccomp 策略

`seccomp` 不建议作为唯一防线，但应作为默认启用的补充层。

### 9.1 策略原则

- 默认允许普通计算所需 syscall
- 明确禁止高风险 syscall
- 不追求极端收紧到影响语言运行时兼容性

### 9.2 建议优先禁掉的 syscall 类别

- 挂载与命名空间管理相关
- 内核调试/观测相关
- `bpf`
- `perf_event_open`
- keyring 相关
- 不需要的特权管理相关调用

### 9.3 实践建议

可以维护多套配置：

- `strict`
- `default`
- `compat`

这样在支持不同语言运行时或不同业务时更容易调整。

## 10. 用户与权限模型

建议采用：

- rootless 优先
- 必要时用短生命周期特权 helper 完成 namespace 和 mount 初始化
- 启动 payload 前丢弃全部不必要 capabilities

能力裁剪建议：

- 默认清空 bounding set
- 不保留 `CAP_SYS_ADMIN`
- 不保留网络、挂载、审计相关能力

如果业务必须使用特权启动器，建议：

- 把高权限代码路径收缩到单独模块
- 避免在复杂逻辑和解析代码中混入高权限操作

## 11. 日志、审计与结果模型

每次执行建议输出统一结果对象：

- `exit_code`
- `term_signal`
- `time_used_ms`
- `wall_time_ms`
- `memory_peak_bytes`
- `stdout_path`
- `stderr_path`
- `status`

其中 `status` 可取：

- `ok`
- `time_limit_exceeded`
- `wall_time_limit_exceeded`
- `memory_limit_exceeded`
- `output_limit_exceeded`
- `runtime_error`
- `sandbox_error`

审计日志建议记录：

- rootfs 准备情况
- 挂载点信息
- cgroup 路径
- seccomp 配置版本
- 最终杀进程原因
- 清理是否成功

## 12. 项目架构

建议采用 workspace 结构：

```text
rust-sandbox/
├─ Cargo.toml
├─ crates/
│  ├─ sandbox-core/
│  ├─ sandbox-supervisor/
│  ├─ sandbox-cli/
│  ├─ sandbox-config/
│  ├─ sandbox-protocol/
│  ├─ sandbox-cgroup/
│  ├─ sandbox-mount/
│  ├─ sandbox-seccomp/
│  └─ sandbox-testkit/
└─ docs/
```

### 12.1 `sandbox-core`

职责：

- 领域模型
- 统一错误类型
- 执行结果定义
- 资源限制结构
- 通用工具函数

### 12.2 `sandbox-config`

职责：

- 解析配置文件
- 校验限制参数
- 提供默认配置模板

### 12.3 `sandbox-protocol`

职责：

- 定义 orchestrator 和 supervisor 间的数据结构
- 定义任务请求、结果对象、日志事件

### 12.4 `sandbox-cgroup`

职责：

- 管理 cgroup v2 目录
- 写入 CPU、内存、pids 限制
- 读取资源统计

### 12.5 `sandbox-mount`

职责：

- rootfs 构建
- bind mount、tmpfs 挂载
- pivot_root/chroot 封装
- 挂载清理

### 12.6 `sandbox-seccomp`

职责：

- seccomp profile 建模
- 规则编译与安装
- 不同模式下的规则集管理

### 12.7 `sandbox-supervisor`

职责：

- namespace 创建
- 子进程拉起
- UID/GID 切换
- capability drop
- 生命周期监控
- 超时和清理

### 12.8 `sandbox-cli`

职责：

- 提供命令行入口
- 本地调试
- 配置文件读取
- 输出执行报告

### 12.9 `sandbox-testkit`

职责：

- 恶意样例
- 压力样例
- 回归测试工具
- fork bomb、内存炸弹、网络探测、文件逃逸等测试程序

## 13. 推荐 Rust 依赖

以下依赖按“实际可用性”而不是“理论最少”来推荐。

### 13.1 基础系统调用与 Unix 封装

- `rustix`  
  推荐作为底层 Unix/Linux 系统接口主力。

- `nix`  
  文档和示例较多，部分场景上手快。

- `libc`  
  当上层封装不完整时直接调用底层接口。

建议：

- 核心路径尽量统一选一个主接口库
- 如果项目偏现代化，可优先 `rustix`

### 13.2 错误处理与日志

- `thiserror`
- `anyhow`
- `tracing`
- `tracing-subscriber`

建议：

- 库层用 `thiserror`
- 应用层用 `anyhow`
- 全项目统一 `tracing`

### 13.3 序列化与配置

- `serde`
- `serde_json`
- `toml`
- `schemars`  
  可选，用于生成配置 schema

### 13.4 CLI 与工具

- `clap`
- `camino`  
  可选，更强类型的 UTF-8 路径

### 13.5 时间与超时

- `tokio`  
  如果需要异步 orchestrator 或并发任务调度

- `mio` 或纯同步实现  
  如果只做单机 supervisor，完全可以先用同步模型

建议：

- supervisor 核心路径先保持同步、简单
- orchestrator 或服务层再按需引入 `tokio`

### 13.6 能力、seccomp 和容器相关

这一层 Rust 生态相对分散，选型前要确认维护状态。

可考虑：

- `caps`
- 针对 seccomp 的社区 crate  
  需要按实际维护情况评估

如果 seccomp crate 不够稳定，务实做法是：

- 先通过 `libc` 自己封装最小 seccomp 安装逻辑

### 13.7 测试与临时目录

- `tempfile`
- `assert_cmd`
- `insta`  
  可选，用于结果快照测试

## 14. 配置示例

可以定义一个任务配置文件：

```toml
[process]
argv = ["/app/run"]
env = ["LANG=C", "PATH=/usr/bin"]
cwd = "/work"

[limits]
cpu_time_ms = 1000
wall_time_ms = 3000
memory_bytes = 268435456
pids = 64
stdout_bytes = 10485760
stderr_bytes = 10485760

[fs]
rootfs = "/opt/sandbox/rootfs/base"
workdir = "/var/lib/sandbox/jobs/job-123"
readonly_bind = ["/opt/runtime/lib:/lib", "/opt/runtime/lib64:/lib64"]
tmpfs = ["/tmp"]

[security]
network = false
mount_proc = true
seccomp_profile = "default"
drop_capabilities = true
```

## 15. 开发阶段建议

推荐按以下顺序实现：

### 第一阶段：最小可运行版本

实现：

- 启动子进程
- 输出重定向
- wall-clock 超时
- 退出码和信号处理

### 第二阶段：基础隔离

实现：

- mount namespace
- PID namespace
- network namespace
- 最小 rootfs

### 第三阶段：资源限制

实现：

- cgroup v2
- pids 限制
- 内存限制
- CPU 统计

### 第四阶段：权限强化

实现：

- user namespace
- capability drop
- seccomp

### 第五阶段：工程化

实现：

- 统一配置模型
- 完整日志与审计
- 攻击样例回归测试
- 崩溃恢复和异常清理

## 16. 需要重点测试的攻击样例

建议至少准备这些测试程序：

- 无限循环
- 无限创建线程
- fork bomb
- 持续申请内存
- 大量写 stdout/stderr
- 不断创建小文件
- 访问宿主机敏感路径
- 创建 socket 并尝试联网
- 使用 Unix domain socket 通信
- 读取 `/proc`
- 调用高风险 syscall
- 进程树退出不干净

## 17. 风险与注意事项

这个项目里最容易出问题的地方通常不是“主路径”，而是失败路径。

需要特别关注：

- seccomp 安装前后执行顺序是否正确
- 挂载失败后是否会留脏状态
- 超时后是否真的杀掉整棵进程树
- cgroup 和 pid namespace 清理是否完整
- rootfs 暴露的动态库和解释器是否超出预期
- `/proc` 是否泄漏了不该看到的信息
- 不同语言运行时是否需要额外 syscall 兼容

## 18. 结论

一个现实可行的 Rust 沙箱方案，最稳妥的路线不是从“最严 syscall 过滤器”开始，而是：

- 以 `namespaces + cgroup v2` 为主体
- 以最小 rootfs 和权限裁剪为环境收缩手段
- 以 `seccomp` 为第二层防护
- 以小型 supervisor 负责生命周期管理

如果目标是评测系统，这样的方案已经能覆盖大部分实际需求。  
如果未来威胁模型提高，还可以继续向：

- LSM
- rootless 强化
- microVM

这些方向演进。
