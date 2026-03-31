# A New Contest Sandbox

根据 `docs/isolate.txt` 的 OCR 文本整理而成的可读版 Markdown。  
This is a readability-oriented Markdown edition derived from the OCR text in `docs/isolate.txt`.

## Source

**English**  
Martin Mareš, Bernard Blackham. *A New Contest Sandbox*. Olympiads in Informatics, 2012, Vol. 6, pp. 100–109.

**中文**  
Martin Mareš 与 Bernard Blackham 合著的《A New Contest Sandbox》，发表于 2012 年《Olympiads in Informatics》第 6 卷，第 100–109 页。

## Abstract

**English**  
Programming contests with automatic evaluation of submitted solutions usually employ a sandbox. Its job is to run the solution in a controlled environment while enforcing security and resource limits. The paper presents a new sandbox construction built on recently added Linux container features. Unlike earlier sandboxes, it introduces essentially no measurable overhead and can handle multi-threaded programs.

**中文**  
自动评测的程序设计竞赛通常都会使用沙箱。沙箱的职责是在受控环境中运行选手程序，同时施加安全限制和资源限制。本文提出了一种建立在 Linux 新增容器能力之上的新型竞赛沙箱。与更早的沙箱相比，它几乎没有可测量的额外开销，并且能够处理多线程程序。

## Keywords

**English**  
automatic grading, sandbox, containers, threads, computer security

**中文**  
自动评测、沙箱、容器、线程、计算机安全

## 1. Introduction

**English**  
Programming contests commonly grade submissions automatically by executing them on batches of test data and checking whether their output is correct. Time and memory limits are also enforced so that efficient solutions can be distinguished from inefficient ones. At the same time, the evaluation system must prevent cheating: the submission must not be able to read protected files, kill unrelated processes, or communicate over the network.

**中文**  
程序设计竞赛通常会通过自动运行提交程序、在一批测试数据上检查输出正确性来完成评测。系统还会施加时间和内存限制，以区分高效与低效的正确解。同时，评测系统还必须防止作弊：选手程序不能读取受保护文件、不能杀死无关进程，也不能通过网络通信。

**English**  
Historically, the most common Linux contest sandbox was a tracing sandbox based on `ptrace`. The kernel would stop the program before each system call, and a monitor process would decide whether the call should continue. This approach can enforce security and resource limits, but it adds overhead, becomes noisy for interactive tasks with many system calls, struggles with multi-threaded programs, and is highly architecture-specific.

**中文**  
历史上，Linux 竞赛环境中最常见的沙箱是基于 `ptrace` 的跟踪式沙箱。内核会在程序发起系统调用前将其暂停，再由监控进程决定是否放行。这个方案虽然能够实现安全控制和资源限制，但它会引入额外开销，在系统调用非常频繁的交互题上噪声较大，对多线程程序支持很差，而且对 CPU 架构高度敏感。

**English**  
The authors propose a new contest sandbox based on Linux namespaces and control groups. These mechanisms were originally intended for partitioning large machines, but they can also be used to isolate untrusted contest programs. The resulting sandbox has much lower overhead and can reliably support multi-process and multi-threaded workloads.

**中文**  
作者提出了一种基于 Linux namespaces 和 control groups 的新型竞赛沙箱。这些机制本来主要用于将大型机器划分为多个隔离节点，但同样可以用于隔离不可信的竞赛程序。基于这些机制实现的沙箱具有更低的开销，并且能够可靠支持多进程和多线程负载。

## 2. Related Work

**English**  
The paper reviews several alternative sandboxing techniques. Linux Security Module based approaches can move policy checking into the kernel and therefore have very low overhead, but their interfaces are unstable across kernel versions and they still do not naturally solve the multi-threading problem. Full virtualization or para-virtualization gives strong isolation, yet the performance overhead and timing variance are considered too large for fair contest judging.

**中文**  
论文回顾了几种替代性的沙箱技术。基于 Linux Security Module 的方案可以把策略检查移入内核，因此开销很低，但它们在不同内核版本之间接口并不稳定，而且依旧不能自然解决多线程问题。完整虚拟化或半虚拟化能提供很强的隔离，但其性能开销和时间波动都过大，不适合用于讲究公平性的竞赛评测。

**English**  
The authors also mention software fault isolation, Native Client, Linux seccomp, and transaction-based systems such as TxBox. These techniques can be powerful in some settings, but many of them require special compilers, kernel modifications, or restrictive execution models. For general contest environments that should work on ordinary Linux distributions and ordinary binaries, such requirements are impractical.

**中文**  
作者还讨论了软件故障隔离、Native Client、Linux seccomp，以及像 TxBox 这样的事务式隔离系统。这些技术在某些场景下很强大，但很多都要求特殊编译器、内核改造，或非常受限的执行模型。对于希望直接运行在普通 Linux 发行版、支持普通二进制程序的竞赛环境来说，这些前提并不现实。

## 3. Requirements for a Contest Sandbox

**English**  
The target environment is a modern, unmodified Linux distribution that can compile and run binaries produced by standard toolchains. The sandbox should therefore not depend on custom kernels, patched language runtimes, or architecture-specific syscall tracing logic. It must isolate the untrusted submission from the trusted rest of the grading infrastructure while keeping deployment practical for contest operators.

**中文**  
目标环境是一套现代、未经修改的 Linux 发行版，能够编译并运行由标准工具链生成的二进制程序。因此，沙箱不应依赖定制内核、打过补丁的语言运行时，或高度依赖架构的系统调用跟踪逻辑。它必须把不可信的选手程序与可信的评测基础设施隔离开来，同时保证部署对竞赛运维来说仍然足够现实可行。

**English**  
The authors enumerate several groups of dangerous or relevant system calls: file access, memory allocation, process and thread creation, signal delivery, IPC primitives, networking, `execve`, sleeping and blocking calls, system time access, and explicit disk flush operations. Each group leads to a concrete sandbox requirement, such as limiting writable filesystem scope, accounting for total memory usage, limiting process counts, prohibiting external networking, and enforcing both CPU and wall-clock time limits.

**中文**  
作者把危险或关键的系统调用分成若干类：文件访问、内存分配、进程与线程创建、信号发送、进程间通信、网络、`execve`、睡眠/阻塞调用、系统时间访问，以及显式刷盘操作。每一类都对应着沙箱的具体要求，例如限制可写文件系统范围、统计总内存使用、限制进程数量、禁止对外联网，以及同时施加 CPU 时间和真实时间限制。

**English**  
One important observation is that traditional UNIX mechanisms are often only per-process, while contest programs may fork multiple processes or use language runtimes that create threads automatically. Therefore, the sandbox must reason about process groups as a whole, not just a single process, especially for CPU time and memory accounting.

**中文**  
一个重要观察是，传统 UNIX 机制往往只对单个进程生效，而竞赛程序可能会 fork 多个子进程，或者使用会自动创建线程的语言运行时。因此，沙箱必须把整个进程组作为管理对象，而不能只盯住单个进程，尤其是在 CPU 时间和内存统计上更是如此。

## 4. Kernel Compartments

### 4.1. Namespaces

**English**  
Linux namespaces provide isolation domains for process visibility, networking, filesystem mounts, and IPC resources. By placing the untrusted program into fresh namespaces, the sandbox can ensure that it sees only its own processes, has no network interfaces, can access only a deliberately prepared filesystem tree, and cannot communicate with the rest of the system through shared-memory or message-passing APIs.

**中文**  
Linux namespaces 为进程可见性、网络、文件系统挂载以及 IPC 资源提供了隔离域。把不可信程序放进新的 namespace 后，沙箱就能保证它只能看到自己的进程、没有网络接口、只能访问预先准备好的文件系统树，并且无法通过共享内存或消息传递 API 与系统其余部分通信。

**English**  
Process namespaces are especially valuable because they form a hierarchy: a process is visible inside its own namespace and its parent namespaces, but not in sibling namespaces. When the top-level process in a process namespace exits, the kernel can terminate the remaining descendants automatically, which greatly simplifies safe cleanup of malicious process trees.

**中文**  
进程 namespace 的价值尤其高，因为它们形成层级结构：进程在自己的 namespace 和父 namespace 中可见，但在兄弟 namespace 中不可见。当某个进程 namespace 的顶层进程退出时，内核可以自动终止其余后代进程，这极大简化了对恶意进程树的安全清理。

### 4.2. Control Groups

**English**  
Namespaces isolate what a program can access, but they do not directly enforce CPU or memory limits. For that, Linux control groups are needed. Control groups allow the kernel to account for resource use across a whole group of related processes and optionally impose limits on that aggregate usage.

**中文**  
Namespaces 负责隔离程序“能接触什么”，但并不直接负责 CPU 或内存限制。为此需要使用 Linux control groups。control groups 允许内核对一整个相关进程组的资源使用进行统一统计，并可对总量施加限制。

**English**  
The paper highlights three controllers relevant to contests: CPU sets for binding workloads to selected cores, the memory controller for limiting overall memory use, and CPU accounting for accurately measuring total CPU time across all processes in the sandbox. Together with namespaces, they provide the security and fairness properties that tracing sandboxes struggle to deliver.

**中文**  
论文重点强调了三个与竞赛场景相关的控制器：用于绑定 CPU 核心的 CPU sets、用于限制总内存使用的 memory controller，以及用于精确统计整个沙箱中所有进程 CPU 时间的 CPU accounting。它们与 namespaces 配合后，才能同时提供 tracing 沙箱难以兼顾的安全性和公平性。

## 5. Implementation

### 5.1. Features

**English**  
The authors implemented the sandbox inside the Moe modular contest system, but designed it as an independent component that can be reused elsewhere. A recent Linux kernel with namespace and control-group support is required. The sandbox offers a lightweight mode based mainly on namespaces and identity separation, and a fuller mode that also enables control groups for total resource accounting across multiple processes and threads.

**中文**  
作者把这个沙箱实现进了 Moe 模块化竞赛系统，但同时把它设计成可以被其他系统复用的独立组件。它要求宿主机使用支持 namespaces 和 control groups 的较新 Linux 内核。沙箱提供两种模式：一种轻量模式主要依赖 namespaces 和身份隔离；另一种完整模式则再叠加 control groups，用来对多进程、多线程程序的总资源使用进行统一统计。

**English**  
The filesystem exposed to the program is built from a custom root on a RAM-backed directory tree. Selected parts of the host filesystem, such as standard libraries, are bind-mounted in read-only mode, while a writable working directory is provided for inputs and outputs. The mechanism is configurable, architecture-independent, and does not need deep knowledge of per-architecture syscall tables.

**中文**  
对程序暴露的文件系统是基于一棵自定义根目录构建的，通常位于 RAM 支撑的目录树上。宿主机文件系统中被选中的部分，比如标准库，会以只读 bind mount 的方式映射进去；同时还会提供一个可写工作目录，用来放输入和输出。整个机制是可配置的、与架构无关的，也不需要依赖特定架构下的系统调用表细节。

### 5.2. Achieving Better Reproducibility

**English**  
The paper emphasizes that fair judging is not only about isolation, but also about reducing measurement noise. Two Linux features are specifically called out: address-space randomization should be disabled to make buggy programs behave consistently, and CPU frequency scaling should be forced to performance mode so that the same solution does not run with noticeably different speeds under different background loads.

**中文**  
论文强调，公平评测不仅关乎隔离，也关乎减少测量噪声。作者特别指出了两个 Linux 特性：应关闭地址空间随机化，使有 bug 的程序行为更一致；应把 CPU 频率缩放固定到性能模式，避免同一程序在不同背景负载下表现出明显不同的运行速度。

## 6. Evaluation

**English**  
The evaluation compares the proposed namespace/control-group based sandbox with a traditional ptrace-based sandbox. For a process that performs one million system calls, the ptrace sandbox introduces significant overhead, while the new sandbox adds effectively none. In the reported experiment, ptrace took 9.26 seconds versus 3.56 seconds for native execution, whereas the new sandbox matched native timing with much lower variance.

**中文**  
评测部分把新沙箱与传统的 ptrace 沙箱进行了对比。对于一个会执行一百万次系统调用的程序，ptrace 沙箱会引入显著开销，而新的 namespace/control-group 沙箱几乎没有额外时间。在文中的实验里，ptrace 方案耗时 9.26 秒，原生执行为 3.56 秒，而新沙箱与原生执行几乎相同，并且方差更小。

## 7. Conclusion

**English**  
The authors conclude that namespaces and control groups form a much better foundation for contest sandboxes than system-call tracing. The approach scales to multi-threaded runtimes, has negligible overhead, and is mostly architecture-independent. They also note one long-term caveat: if future kernels introduce new objects or interfaces outside the namespaces the sandbox knows about, the sandbox must be updated accordingly.

**中文**  
作者的结论是：与系统调用跟踪相比，namespaces 和 control groups 更适合作为竞赛沙箱的基础。这个方案能够支持多线程运行时，开销极小，而且基本不依赖具体架构。与此同时，作者也提醒了一个长期风险：如果未来内核加入了新的对象或接口，而它们不在沙箱已知的 namespace 覆盖范围内，沙箱仍然需要持续更新。

## References

**English**  
The paper cites earlier work on contest security, grading systems, Linux system interfaces, timing fairness, software fault isolation, Native Client, and related sandbox research. Representative references include Forišek (2006), Mareš (2007, 2009, 2011), Merry (2009, 2010), Wahbe et al. (1993), Yee et al. (2009), and Jana et al. (2011).

**中文**  
本文引用了竞赛安全、评测系统、Linux 系统接口、时间公平性、软件故障隔离、Native Client 以及相关沙箱研究中的多篇工作。较具代表性的参考文献包括 Forišek（2006）、Mareš（2007、2009、2011）、Merry（2009、2010）、Wahbe 等（1993）、Yee 等（2009）以及 Jana 等（2011）。
