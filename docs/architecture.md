# Sandbox Architecture and Runtime Sequence

## 1. 架构设计图 (Architecture Diagram)

架构图展示了整个沙箱项目各组件的分层关系，从外部请求接入层一直到最底层的系统资源隔离层。

```mermaid
flowchart TB
    subgraph api["接入控制层"]
        cli["sandbox-cli"]
        http["sandbox-protocol"]
    end

    subgraph supervisor["生命周期管理层"]
        sup["sandbox-supervisor"]
    end

    subgraph core["核心隔离层"]
        ctl["sandbox-core"]
        cfg["sandbox-config"]
        mount["sandbox-mount"]
        cgrp["sandbox-cgroup"]
        sec["sandbox-seccomp"]
    end

    subgraph system["OS 提供保障"]
        payload["Sandbox Payload"]
        ns["Namespaces"]
        cgw["Cgroup V2"]
        bpf["Seccomp BPF"]
    end

    cli --> sup
    http --> sup

    sup --> cfg
    sup --> ctl

    ctl --> mount
    ctl --> cgrp
    ctl --> sec
    ctl --> payload

    mount --> ns
    cgrp --> cgw
    sec --> bpf
```

## 2. 运行时序图 (Runtime Sequence Diagram)

时序图详细描述了一次不可信代码执行的完整生命周期，对应于设计文档中的“生命周期设计”。

```mermaid
sequenceDiagram
    autonumber
    participant Client as Orchestrator / Client
    participant Sup as Sandbox Supervisor
    participant Cgroup as Config & Cgroup
    participant Mount as Mount & Namespace
    participant Sec as Seccomp Filter
    participant Payload as Untrusted Payload (Process)

    Client->>Sup: 解析配置并发起 Execution Request
    activate Sup
    
    Sup->>Cgroup: 验证配置并准备对应的 Cgroup V2 目录
    Cgroup-->>Sup: Cgroup 准备就绪
    
    Sup->>Cgroup: 写入资源限制 (CPU, Memory, Pids)
    
    Sup->>Mount: 准备任务的只读 RootFS 和写操作 WorkDir
    Mount-->>Sup: Mount 点准备完毕
    
    Sup->>Mount: 创建新的 Namespace (User, PID, Mount, Net, IPC)
    
    Sup->>Sup: 配置 rlimit, 环境变量, io stdin/stdout 等
    Sup->>Sup: 丢弃 Capabilities (Drop privileges)
    
    Sup->>Sec: 系统调用过滤(加载 seccomp 规则)
    Sec-->>Sup: 规则生效 (e.g., block ptrace/socket)
    
    Sup->>Payload: 启动目标进程 (Exec / Spawn)
    activate Payload
    
    par 进程监控
        Sup->>Sup: PIDFD / wait / timer 监控运行状态
    and 资源消耗
        Payload->>Cgroup: 资源占用统计到 cgroup
    end
    
    alt 到达时间限制 / 资源超标
        Sup->>Payload: 立即发送 SIGKILL 终止进程
    else
        Payload-->>Sup: 进程正常或异常退出
    end
    deactivate Payload
    
    Sup->>Sup: 统一终止进程树 (确保无僵尸进程和 fork bomb)
    Sup->>Mount: 回收卸载挂载点 (清理 rootfs)
    Sup->>Cgroup: 删除任务专有 Cgroup
    
    Sup-->>Client: 返回结果 (Execution Result / Logs / Status)
    deactivate Sup
```
