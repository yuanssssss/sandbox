# IOI `isolate` 沙箱设计总结与 Rust 学习路线

## 1. 背景

在 IOI 这类自动评测系统中，评测机需要运行选手提交的、默认不可信的程序。  
因此，评测系统必须同时满足两类目标：

- 保证宿主机和评测系统其他部分的安全
- 对提交程序施加时间、内存、磁盘等资源限制

本文基于两篇论文进行总结：

- `A New Contest Sandbox` (2012)
- `Security of Grading Systems` (2021)

前者主要介绍 `isolate` 沙箱本身的设计；后者则从整个评测系统安全的角度，讨论威胁模型、典型攻击方式和对应防御措施。

## 2. 两篇论文的简要概述

### 2.1 A New Contest Sandbox

这篇论文提出了一个新的竞赛沙箱 `isolate`。  
它不再采用早期常见的 `ptrace` 系统调用跟踪方案，而是基于 Linux 内核提供的容器化机制：

- namespaces
- control groups

论文的核心结论是：

- 这种沙箱几乎没有可测的运行时开销
- 可以正确处理多进程、多线程程序
- 比基于 `ptrace` 的方案更适合现代竞赛环境

这对于 Java、C#、Erlang 之类运行时天然会创建多个线程的语言尤其重要。

### 2.2 Security of Grading Systems

这篇论文不是只讨论某一个沙箱实现，而是把视角提升到整个评测系统。

作者重点讨论了：

- 沙箱设计中的典型安全问题
- 评测阶段和编译阶段的风险
- grader/checker 与选手程序混合执行的风险
- DoS、信息泄漏、侧信道、公平性等问题

论文的重要结论是：

- 安全不能只靠沙箱本身
- 必须把可信代码和不可信代码严格分层
- 编译、执行、交互、判题都应视为独立的安全边界

## 3. `isolate` 的核心设计思路

`isolate` 的关键思路不是“逐个检查程序做了什么”，而是“从根上限制程序能接触到什么”。

### 3.1 为什么不继续用 `ptrace`

早期基于 `ptrace` 的沙箱有几个明显问题：

- 每个系统调用都要进入监控路径，性能开销大
- 多线程场景下容易出现 TOCTOU 问题
- 对 CPU 架构和系统调用细节依赖较强
- 对高 syscall 负载或交互式任务不够友好

### 3.2 `isolate` 的方法

`isolate` 转向了 Linux 提供的隔离原语：

- 用 `namespaces` 隔离进程可见的内核资源
- 用 `cgroups` 统计和限制整个进程组的资源使用
- 用最小化文件系统视图控制程序可访问的文件与工具

这意味着：

- 程序可以调用很多 syscall，但大多数对象在它的视图中根本不存在
- 安全边界从“过滤行为”变成了“收缩可见范围”
- 既降低了性能损失，也减轻了多线程竞争导致的检查缺陷

## 4. `isolate` 为保证安全实施了哪些措施

### 4.1 进程隔离

使用 `PID namespace`。

效果：

- 沙箱内程序只能看到本命名空间内的进程
- 无法直接干扰宿主机上的其他进程
- 顶层进程退出后，沙箱内部整个进程树可以被一并回收

### 4.2 网络隔离

使用 `network namespace`。

效果：

- 不给网络设备
- 通常连 loopback 都不可用
- 防止外网通信、本地网络通信和借网络绕过限制

### 4.3 文件系统隔离

使用 `mount/filesystem namespace` 配合定制根目录。

效果：

- 为程序构造一个最小可见文件系统
- 只挂载必要的标准库和工作目录
- 标准库通常只读挂载
- 工作目录单独可写
- 可配合磁盘配额限制写入总量

相比传统 `chroot`，这种方式更不容易逃逸。

### 4.4 IPC 隔离

使用 `IPC namespace`。

效果：

- 隔离共享内存、消息队列等通信机制
- 防止选手程序与系统上其他进程交换数据

### 4.5 用户身份隔离

让沙箱进程运行在独立 UID/GID 下。

效果：

- 依靠 UNIX 权限模型限制文件访问
- 阻止向其他用户的进程发送信号
- 降低对宿主系统的直接干扰能力

### 4.6 资源总量控制

使用 `cgroups` 控制整组进程，而不是只控制单个进程。

包括：

- 总内存限制
- CPU 时间统计
- CPU 核绑定

这可以防止：

- fork bomb
- 多进程分摊资源绕过限制
- 多线程并行抢核影响公平性

### 4.7 双时间限制

同时限制：

- CPU time
- wall-clock time

这样既能处理死循环，也能防止程序通过睡眠、阻塞或等待事件长期占住评测流程。

### 4.8 磁盘写入限制

论文明确指出，只限制单文件大小不够，需要限制总磁盘使用量。

效果：

- 防止通过大量小文件或持续输出写爆磁盘
- 降低对同机其他评测任务的影响

### 4.9 最小化执行环境

`isolate` 不试图完全禁止 `execve`，而是尽量不把额外程序放进沙箱文件系统里。

效果：

- 防止选手借助额外工具完成本不应允许的工作
- 可以通过 `noexec` 等挂载选项进一步限制执行

### 4.10 隐藏管理信息

在 2021 年的综述论文中，作者特别提到 `isolate` 还额外隐藏了 sandbox manager。

效果：

- 防止选手通过 `/proc` 看到管理进程参数
- 避免泄漏测试编号、限制参数、内部路径等敏感信息

## 5. 从评测系统角度看，`isolate` 解决了什么

`isolate` 主要解决了以下三类问题：

### 5.1 系统完整性

- 防止随意访问宿主机文件
- 防止杀死或干扰其他进程
- 防止联网
- 防止跨进程通信

### 5.2 资源滥用

- 防止死循环
- 防止内存耗尽
- 防止 fork bomb
- 防止磁盘打满

### 5.3 评测公平性

- 降低 syscall 监控开销
- 减少计时噪声
- 提高交互题和高 syscall 程序的可测量性

## 6. `isolate` 没有完全解决的问题

即使 `isolate` 设计优秀，它也不是整个评测系统安全的全部答案。

### 6.1 可信代码与不可信代码分层

grader/checker 不应和选手代码在同一进程中运行。  
否则选手程序可能直接读写 grader 状态，甚至伪造判题结果。

### 6.2 编译阶段同样危险

编译器、构建脚本、语言运行时工具链也会执行不可信输入。  
因此“只沙箱运行阶段、不沙箱编译阶段”是不够的。

### 6.3 侧信道问题

例如：

- 时间观测
- CPU cache
- socket buffer
- 微架构漏洞

这些问题很难靠传统 namespace/cgroup 彻底消除。

### 6.4 对新内核对象的适配

2012 论文自己也承认：如果未来 Linux 增加了新的可访问内核对象，而这些对象没有被当前隔离机制覆盖，就需要继续扩展沙箱策略。

## 7. 基于目前技术，可以如何改进

如果今天重新设计或增强一个类似 `isolate` 的竞赛沙箱，可以考虑以下方向。

### 7.1 使用 `cgroup v2`

现代 Linux 更推荐 `cgroup v2`。

优点：

- 统一的层级结构
- 更一致的资源模型
- 更便于管理和观测

### 7.2 在 namespace 之外叠加 `seccomp-bpf`

可以把 `seccomp` 当作第二道防线，而不是主隔离机制。

适合额外限制：

- `bpf`
- `perf_event_open`
- 与挂载、命名空间管理相关的高风险 syscall
- 不必要的 socket/address family

这样能形成 defense-in-depth。

### 7.3 引入 LSM

例如：

- `Landlock`
- `AppArmor`
- `SELinux`

作用是为文件访问和进程行为提供额外的强制访问控制层。

### 7.4 更彻底的最小化根文件系统

可以考虑：

- 只读 rootfs
- `tmpfs`
- `overlayfs`

目标是让沙箱环境更接近不可变镜像，便于审计和复现。

### 7.5 更严格的挂载选项和设备控制

对不可信可写目录默认采用：

- `noexec`
- `nosuid`
- `nodev`

同时尽量减少暴露：

- `/proc`
- `/sys`
- 设备节点

### 7.6 使用 rootless 模式或减少特权代码路径

如果实现允许，尽量减少高权限管理代码的复杂度。  
沙箱管理器本身也是攻击面，代码越小越容易审计。

### 7.7 更系统地处理侧信道

高安全需求下可以考虑：

- 固定 CPU 核
- 禁用 SMT/超线程
- 让不同选手任务不与敏感服务混跑
- 使用更独立的评测节点

### 7.8 对整个评测链路做分域隔离

建议把以下组件拆开：

- 编译
- 运行
- checker
- 交互器

不同阶段放入不同沙箱或不同信任域中，而不是只保护“运行选手程序”这一步。

### 7.9 在更强威胁模型下引入 microVM

如果面对的是公开在线评测平台、高价值目标或更强攻击者，可以考虑：

- Firecracker
- Kata Containers
- gVisor

这些方案一般比纯 namespace 沙箱更重，但安全边界通常更强。

## 8. 结论

`isolate` 的设计在今天依然很有代表性。  
它的核心价值不是某一个单独的 Linux 特性，而是如下思路：

- 通过缩小程序可见世界来实现隔离
- 通过对整个进程组计量和限额来实现资源控制
- 通过最小化环境暴露来兼顾性能、安全与公平性

对于 IOI 这类评测系统来说，`isolate` 是一个非常合理的核心执行沙箱。  
但在现代安全要求下，更稳妥的方案通常是：

- `namespaces + cgroups`
- 再叠加 `seccomp`
- 再叠加 LSM
- 再把编译、执行、checker、交互器彻底分层

如果威胁模型更强，则继续向 microVM 方向提升隔离级别。

## 9. 如果想用 Rust 制作一个沙箱，推荐怎么学

如果目标是“用 Rust 写一个 Linux 沙箱”，建议把学习分成四层。

### 9.1 第一层：Rust 语言基础与系统编程能力

优先学习：

- The Rust Programming Language  
  官方教材，先把所有权、错误处理、trait、并发基础打稳。

- Rust by Example  
  适合快速查语法和小片段。

- Rust Atomics and Locks  
  如果后面要写高可靠的沙箱管理器或调度器，这本书很有价值。

### 9.2 第二层：Linux 系统接口

需要重点掌握：

- `fork/execve/waitpid`
- `clone` / `clone3`
- namespaces
- `setrlimit`
- `cgroups`
- mount 系统调用
- `seccomp`
- 信号
- `pidfd`
- 文件描述符继承与关闭

建议资料：

- The Linux Programming Interface, Michael Kerrisk
- man pages  
  重点看：`namespaces(7)`、`cgroups(7)`、`seccomp(2)`、`clone(2)`、`mount(2)`、`pivot_root(2)`、`unshare(2)`、`setrlimit(2)`
- Linux kernel documentation  
  重点看 cgroup v2、seccomp、namespace 相关文档

### 9.3 第三层：Rust 与 Linux syscall 绑定

推荐先从这些 crate 熟悉生态：

- `nix`  
  Rust 下最常见的 Unix 系统调用封装，适合入门和快速原型。

- `rustix`  
  更现代、更贴近底层，也常用于系统级项目。

- `libc`  
  当上层封装不够用时直接调底层接口。

- `caps`  
  处理 Linux capabilities 时可参考。

如果你未来要上 `seccomp-bpf`，也可以专门找 Rust 社区中对 seccomp 规则生成的库，但这部分生态相对分散，实践时要先看维护状态。

### 9.4 第四层：读成熟项目

如果你真的想做“能用的沙箱”，最重要的是读现有实现。

建议看这些项目的源码或设计：

- `isolate`
- `nsjail`
- `bubblewrap`
- `firejail`
- `runc`
- `youki`  
  这是 Rust 写的 OCI runtime，很适合观察 Rust 如何组织 Linux 容器相关代码。

其中：

- `bubblewrap` 很适合学习最小化 namespace/mount 隔离
- `nsjail` 很适合学习竞赛式或工具式沙箱的配置思路
- `youki` 很适合学习 Rust 在容器/runtime 方向的工程化写法

## 10. 推荐的 Rust 沙箱学习路径

一个比较稳妥的实作顺序如下：

1. 先用 Rust 写一个最小进程运行器  
   只做 `fork/exec/wait`、超时、输出重定向、退出码处理。

2. 加入资源限制  
   先做 `setrlimit`，再做 `cgroup v2`。

3. 加入 mount namespace 和最小 rootfs  
   先做只读库目录和独立工作目录。

4. 加入 PID、IPC、network namespace  
   让程序拥有隔离的进程视图、IPC 和网络环境。

5. 加入 `seccomp`  
   作为第二层防护。

6. 加入审计与可观测性  
   比如日志、资源用量、超时原因、信号终止原因。

7. 最后再考虑工程化问题  
   包括配置系统、测试样例、攻击样例、错误恢复、并发评测调度。

## 11. 额外建议

如果你的目标不是“研究型沙箱”，而是“做一个能上线的评测沙箱”，建议：

- 先做 Linux-only
- 先做最小功能集
- 先验证威胁模型
- 不要一开始追求支持所有语言和所有内核版本
- 先把 mount、PID、network、cgroup、seccomp 这条主线做扎实

真正难的部分通常不是“能跑起来”，而是：

- 默认配置是否安全
- 资源统计是否可靠
- 失败时是否能彻底清理残留进程和挂载点
- 出错路径是否会留下提权或逃逸机会

---

## 12. 推荐资料清单

### Rust

- The Rust Programming Language  
  https://doc.rust-lang.org/book/

- Rust by Example  
  https://doc.rust-lang.org/rust-by-example/

- Rust Atomics and Locks  
  https://marabos.nl/atomics/

### Linux / Sandbox / Containers

- The Linux Programming Interface  
  https://man7.org/tlpi/

- Linux man-pages  
  https://man7.org/linux/man-pages/

- Kernel docs: namespaces  
  https://www.kernel.org/doc/html/latest/admin-guide/namespaces/index.html

- Kernel docs: cgroup v2  
  https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html

- Kernel docs: seccomp  
  https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html

### 参考项目

- isolate  
  https://www.ucw.cz/isolate/

- nsjail  
  https://github.com/google/nsjail

- bubblewrap  
  https://github.com/containers/bubblewrap

- youki  
  https://github.com/youki-dev/youki

- runc  
  https://github.com/opencontainers/runc
