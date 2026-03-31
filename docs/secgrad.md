# Security of Grading Systems

根据 `docs/secgrad.txt` 的 OCR 文本整理而成的可读版 Markdown。  
This is a readability-oriented Markdown edition derived from the OCR text in `docs/secgrad.txt`.

## Source

**English**  
Martin Mareš. *Security of Grading Systems*. Olympiads in Informatics, 2021, Vol. 15, pp. 37–52.

**中文**  
Martin Mareš 的《Security of Grading Systems》，发表于 2021 年《Olympiads in Informatics》第 15 卷，第 37–52 页。

## Abstract

**English**  
Programming contests often rely on automatic grading of submissions. Because graders execute potentially malicious contestant code, they face a broad set of security problems. This paper surveys concrete attacks against grading systems and discusses counter-measures.

**中文**  
程序设计竞赛通常依赖自动评测提交结果。由于评测器需要运行潜在恶意的选手代码，它面临一整套安全问题。本文系统梳理了针对评测系统的具体攻击方式，并讨论了相应的防御措施。

## Keywords

**English**  
automatic grading, security, sandbox, covert channels

**中文**  
自动评测、安全、沙箱、隐蔽信道

## 1. Introduction

**English**  
Automatic grading takes a submitted solution, compiles it, executes it on test inputs, and checks whether the resulting outputs are correct. Time and memory limits are also enforced so that efficient programs can be distinguished from inefficient ones. In a complete contest platform, the grader is only one component among many, but it is the component that directly runs untrusted contestant code and therefore becomes the main security boundary.

**中文**  
自动评测会读取提交的程序，对其进行编译，在测试数据上运行，并检查输出是否正确。同时系统还会施加时间和内存限制，以便区分高效与低效的程序。在完整的竞赛平台中，评测器只是众多组件之一，但它是那个直接执行不可信选手代码的组件，因此天然成为最关键的安全边界。

**English**  
The paper focuses on attacks that target the integrity of the grading infrastructure itself rather than cheating through external communication. It surveys older literature, then updates the threat model for modern Linux-based contest systems that already use namespaces, control groups, containers, and more complex language runtimes.

**中文**  
本文关注的是直接破坏评测基础设施完整性的攻击，而不是从外部渠道获取帮助那类作弊行为。作者先回顾了较早的研究，然后针对已经广泛使用 namespaces、control groups、容器以及复杂语言运行时的现代 Linux 竞赛系统，重新更新威胁模型。

## 2. Obsolete Attacks

### 2.1. Timing

**English**  
Earlier Linux schedulers often accounted CPU time by periodic timer ticks instead of by precise timestamps at context switches. That opened the door to timing attacks in which a process deliberately slept whenever the timer tick arrived, making its measured runtime appear artificially low. With the Completely Fair Scheduler, Linux switched to better accounting and these attacks are no longer practical in their old form.

**中文**  
早期 Linux 调度器经常依赖周期性时钟采样，而不是在上下文切换时使用精确时间戳来统计 CPU 时间。这就给了时序攻击可乘之机：进程可以在时钟 tick 到来时故意休眠，让测得的运行时间被人为压低。随着 Completely Fair Scheduler 的引入，Linux 改用了更准确的统计方式，这类旧式攻击已经不再现实。

### 2.2. Time-of-check to Time-of-use Race Conditions

**English**  
The classical ptrace sandbox model suffers from time-of-check to time-of-use races. If one thread prepares a syscall while another thread rewrites its memory arguments after the sandbox manager has inspected them, the kernel may execute something different from what was checked. This makes syscall-filter sandboxes fundamentally unsafe for multi-threaded programs.

**中文**  
经典的 ptrace 沙箱模型存在典型的 TOCTOU（检查时与使用时不一致）竞争条件。如果一个线程准备系统调用，而另一个线程在沙箱管理器检查完参数后改写了这块内存，那么内核最终执行的内容就可能与检查时看到的不一致。这使得基于系统调用过滤的沙箱在多线程程序面前从根本上不安全。

**English**  
Modern contest systems mostly moved to sandboxing based on namespaces. In such systems, the kernel restricts what resources the process can reach instead of checking every syscall in user space. Even when seccomp is added as a second line of defense, its BPF programs can inspect only direct syscall arguments and therefore avoid the classic user-memory TOCTOU problem.

**中文**  
现代竞赛系统大多已经转向基于 namespaces 的沙箱。在这种模型下，内核通过限制进程能接触到的资源范围来实现隔离，而不是在用户态逐个检查每次系统调用。即使再叠加 seccomp 作为第二道防线，它的 BPF 程序也只能查看系统调用的直接参数，因此可以绕开传统的用户内存 TOCTOU 问题。

## 3. Denial-of-Service Attacks

### 3.1. Execution Time

**English**  
The simplest DoS attacks are infinite loops, infinite recursion, and unbounded allocation loops, all of which are handled by normal time and memory limits. More subtle examples include fork bombs, where many small processes are created so that per-process limits become ineffective; the correct response is to cap the total resources used by the whole sandbox, not by just one process.

**中文**  
最简单的 DoS 攻击包括死循环、无限递归以及无限分配内存的循环，这些通常能靠常规的时间和内存限制挡住。更隐蔽的例子是 fork bomb：程序会制造大量小进程，从而绕过单进程限制；正确的应对方式是限制整个沙箱进程组的总资源使用量，而不是只盯住单个进程。

**English**  
Disk filling is another practical attack vector. Limiting a single file size is insufficient, because a malicious program can create many files instead. The paper therefore recommends disk quotas tied to the sandbox identity rather than narrower per-file mechanisms.

**中文**  
打满磁盘也是一种非常现实的攻击方式。只限制单个文件大小远远不够，因为恶意程序完全可以改成创建很多小文件。因此，论文建议把磁盘配额绑定到沙箱身份或沙箱整体，而不是依赖单文件限制。

### 3.2. Compilation Time

**English**  
Compilation itself is a security and availability problem. C++ template chains can make compilation arbitrarily slow, includes from `/dev/zero` can explode memory consumption, includes from `/dev/urandom` can burn time, and specially crafted static data can force huge object files. In other words, “only sandbox the run stage” is not a sufficient security strategy.

**中文**  
编译阶段本身就是安全与可用性问题。C++ 模板链可以让编译时间任意增长，从 `/dev/zero` include 会导致内存爆炸，从 `/dev/urandom` include 会大量耗时，而精心构造的静态数据还能生成巨大的目标文件。换句话说，“只对运行阶段做沙箱”并不能构成完整的安全策略。

## 4. Attacks on In-Process Graders

**English**  
IOI-style tasks often expose an API between the contestant's solution and the grader. This model has usability advantages, especially for interactive tasks, but the security cost is severe: trusted grader code and untrusted contestant code share a single address space. The solution can read grader state, tamper with it, or even modify the grader's code.

**中文**  
IOI 风格的题目通常会给选手程序和 grader 之间定义一套 API。这个模型在可用性上很有优势，尤其适合交互题，但它的安全代价也非常高：可信的 grader 代码和不可信的选手代码共享同一个地址空间。选手程序可以读取 grader 的状态、篡改它，甚至修改 grader 的代码。

### 4.1. Exchanging Library Functions

**English**  
With static linking, a contestant can sometimes interpose standard-library functions used by the grader. If the grader calls `write()` and the contestant supplies another `write()` symbol earlier in link resolution, the grader may end up invoking contestant-controlled code. A mitigation is two-step linking so that the grader resolves its own library dependencies before it is linked together with the solution.

**中文**  
在静态链接场景下，选手有时可以插桩 grader 使用的标准库函数。比如 grader 想调用 `write()`，但如果选手在链接解析顺序上更早提供了另一个 `write()` 符号，grader 最终就可能调用到选手控制的实现。一个缓解方式是使用两阶段链接，让 grader 先独立解析自己的库依赖，再与选手程序链接到一起。

### 4.2. Rolling Back Grader State

**English**  
If the grader keeps internal state, such as the number of allowed queries in an interactive task, the solution can exploit process creation to “roll back” that state. By forking a process, using grader functionality inside the child, and then discarding the child, the main process keeps an earlier snapshot of the grader state while still learning useful information. This attack is much easier than reconstructing and manually editing the grader's memory.

**中文**  
如果 grader 内部保存了状态，例如交互题中允许查询的次数，选手就可以利用进程创建来“回滚”这个状态。方法是 fork 一个子进程，在子进程里使用 grader 的功能，随后丢弃子进程；这样主进程仍保留较早的 grader 状态快照，却已经拿到了有用信息。这种攻击比手动定位并修改 grader 内存容易得多。

### 4.3. Proper Design of Graders

**English**  
The paper's conclusion is uncompromising: security by obscurity inside a shared process is fundamentally unsound. For batch tasks, correctness checking should happen outside the sandbox after the solution stops. For interactive tasks, communication should cross a real boundary such as a pipe, a UNIX-domain socket, or—if necessary and carefully designed—shared memory with explicit copying to avoid TOCTOU hazards.

**中文**  
论文在这里的结论非常明确：在共享进程中依赖“安全靠隐藏”从根本上是不可靠的。对于批处理题，正确性检查应该在选手程序结束之后、沙箱外部完成；对于交互题，通信应穿过真实的边界，例如 pipe、UNIX-domain socket，或者在非常谨慎设计下使用共享内存，并通过显式复制来规避 TOCTOU 风险。

## 5. Covert Channels

### 5.1. Secrets Lying on the Disk

**English**  
Contest systems often accidentally expose secret inputs, reference outputs, or even reference solutions through the filesystem. Namespace-based sandboxes reduce the risk during execution, but compilation environments are often granted overly broad read access because toolchains need many files. The paper points out that anything available during compilation can often be smuggled back into the final executable, for example through assembler directives such as `.incbin`.

**中文**  
竞赛系统经常会因为配置失误，把秘密输入、标准输出，甚至参考解暴露在文件系统中。基于 namespace 的沙箱能降低运行阶段的风险，但编译环境常常因为工具链依赖太多文件而被授予过宽的只读访问权限。论文指出，只要编译阶段能看到某个文件，攻击者往往就能把它偷偷带进最终程序里，例如借助汇编器的 `.incbin` 指令。

### 5.2. Grader Feedback as a Covert Channel

**English**  
Submission feedback itself is a low-bandwidth covert channel. Even if the system only reports verdict, time, and memory, a contestant can intentionally encode a few bits of information in each of these fields. Across repeated submissions, that can leak meaningful properties of secret test data. The defense is to keep feedback coarse and to avoid tasks whose hidden tests have very low entropy.

**中文**  
提交反馈本身就是一种低带宽隐蔽信道。即便系统只返回 verdict、时间和内存，选手也可以故意在这些字段中编码少量信息。多次提交累积起来，就可能泄露秘密测试数据的重要特征。对应的防御策略是让反馈尽量粗粒度，并避免设计那些隐藏数据熵值很低的任务。

### 5.3. /proc File System

**English**  
The `/proc` filesystem can leak sensitive process metadata, especially command-line arguments. Contest infrastructure should therefore avoid passing secrets through process arguments. Sandboxes based on process namespaces already help by hiding unrelated processes, and Isolate goes further by hiding even the sandbox manager itself from the jailed process view.

**中文**  
`/proc` 文件系统可能泄露敏感的进程元数据，尤其是命令行参数。因此，竞赛基础设施不应通过进程参数传递秘密信息。基于进程 namespace 的沙箱已经能通过隐藏无关进程来缓解问题，而 Isolate 更进一步，甚至会把 sandbox manager 自己也从沙箱视图里隐藏起来。

## 6. Cross-Language Attacks

**English**  
Giving slower languages such as Python looser time limits creates another attack surface: contestants can embed a fast C++ solution inside a Python wrapper, reconstruct the native binary at runtime, and execute it under Python limits. Similar tricks can be adapted to IOI-style APIs by compiling native code into language-specific extension modules. This makes language-specific limits much harder to defend than they first appear.

**中文**  
给较慢语言（如 Python）放宽时间限制也会带来新的攻击面：选手可以把高性能的 C++ 解嵌进 Python 包装层，在运行时重建原生二进制，并在 Python 的时间限制下执行它。类似技巧还可以通过把原生代码编译成语言扩展模块的方式适配 IOI 风格 API。这说明，按语言给不同时间限制远比表面看上去更难防守。

## 7. Other Attacks

### 7.1. Using Threads to Increase Cache Size

**English**  
Even if total CPU time is accounted across all threads, parallel threads can sometimes outperform a single-threaded version because they effectively gain access to more cache. If the working set is only slightly larger than one L3 cache, splitting work across cores may reduce memory-latency costs. The paper suggests pinning the sandbox to a single core to remove this advantage.

**中文**  
即便系统把所有线程的总 CPU 时间都记在一起，多线程有时仍可能比单线程更快，因为它们实际上获得了更大的缓存容量。如果工作集只比单个 L3 cache 稍大一些，把任务拆到多个核心上可能降低内存访问延迟。论文建议把沙箱绑到单个核心上，从而消除这种优势。

### 7.2. Storing Data in Socket Buffers

**English**  
When memory is measured poorly, data can be hidden in socket buffers outside normal process address space. Traditional UNIX limits may miss this, whereas memory control groups can account for it. Socket buffers are therefore a concrete example of why total-resource accounting at the sandbox level matters.

**中文**  
如果内存统计机制不完善，数据就可能被藏进套接字缓冲区中，从而逃离普通进程地址空间的统计范围。传统 UNIX 限制可能看不到这部分，而 memory control groups 则能够把它统计进去。套接字缓冲区因此成为“为什么必须在沙箱整体层面做总量统计”的一个具体例子。

### 7.3. Security Issues in Processors

**English**  
Processor vulnerabilities such as Meltdown and Spectre showed that security boundaries can be undermined by microarchitectural side effects. The author's assessment is that properly sandboxed contest systems can largely rely on the mitigations already implemented in Linux and modern software stacks; the much bigger practical risk remains design mistakes that place trusted and untrusted logic too close together.

**中文**  
Meltdown、Spectre 等处理器漏洞说明，微架构副作用也可能破坏本应存在的安全边界。作者的判断是：对于 properly sandboxed 的竞赛系统，通常可以依赖 Linux 和现代软件栈已经实现的缓解措施；更大的现实风险，依然是那些让可信逻辑和不可信逻辑靠得过近的设计错误。

## 8. Conclusion

**English**  
The paper's final recommendations are clear: separate trusted and untrusted parts of the contest system rigorously; sandbox both compilation and execution; avoid mixing grader correctness logic with contestant code in the same process; limit total time, memory, and disk usage; minimize the bandwidth of feedback-based covert channels; and remain vigilant because systems and attacks continue to evolve.

**中文**  
论文最后给出的建议非常明确：要严格分离竞赛系统中的可信部分与不可信部分；对编译阶段和执行阶段都实施沙箱；不要让负责判定正确性的 grader 逻辑与选手代码在同一进程中混跑；限制总时间、总内存和总磁盘使用；尽量压缩反馈型隐蔽信道的带宽；同时保持持续警惕，因为系统和攻击手段都会不断演化。

## References

**English**  
The references cover contest-system security, Linux scheduling, Linux manual pages, speculative-execution attacks, grading-system design, and cross-language attack tooling. Representative works include Forišek (2006), Mareš (2011), Blackham and Mareš (2012), Edge (2015), Tsafrir et al. (2007), Peveler et al. (2019), and Lukeš & Šraier (2020).

**中文**  
参考文献涵盖了竞赛系统安全、Linux 调度、Linux 手册页、推测执行攻击、评测系统设计以及跨语言攻击工具等主题。较具代表性的工作包括 Forišek（2006）、Mareš（2011）、Blackham 与 Mareš（2012）、Edge（2015）、Tsafrir 等（2007）、Peveler 等（2019）以及 Lukeš 与 Šraier（2020）。
