# examples/01

这个目录现在提供两组样例：

- 本地 CLI 样例：
  - 多文件正常程序编译与运行
  - 死循环触发超时
  - 爆内存触发 `memory.max`
  - `ptrace` 与 `socket` 这类高风险 syscall 被 seccomp 拦截
- 多阶段 judge job 样例：
  - C++ 隔离编译 -> 运行 -> checker
  - Java 隔离编译 -> 运行 -> checker
  - Python 隔离编译 -> 运行 -> checker

## 文件说明

- `main.c` + `extra.c` + `extra.h`
  - 正常的多文件 C 程序
- `memory_limit.c`
  - 默认申请并逐页触碰 `64 MiB` 内存，用于触发 cgroup 内存限制
- `timeout.c`
  - 忙等死循环，用于触发 wall-clock timeout
- `danger_ptrace.c`
  - 尝试调用 `ptrace(PTRACE_TRACEME)`，在 `default` seccomp 下应被拒绝
- `danger_socket.c`
  - 尝试创建 `AF_INET` socket，在 `strict` seccomp 下应被拒绝
- `languages/cpp/main.cpp`
  - 最小 C++ judge job 样例，输出 `sum=7`
- `languages/java/Main.java`
  - 最小 Java judge job 样例，输出 `sum=7`
- `languages/python/solution.py`
  - 最小 Python judge job 样例，输出 `sum=7`
- `judge-jobs/*.json.in`
  - 供 `sandbox-judge-cpp` / `sandbox-judge-java` / `sandbox-judge-python` 渲染并提交的协议模板

## 本地编译

```bash
make -f examples/01/Makefile all
```

产物会放到 `examples/01/build/`：

- `hello`
- `memory_limit`
- `timeout`
- `danger_ptrace`
- `danger_socket`

## 沙箱配置

配置文件都放在 `examples/01/configs/`：

- `compile.toml`
  - 在沙箱 supervisor 中执行 `make clean all`
  - 配合 `sandbox-cli compile --source-dir . --output-dir examples/01/build` 使用
  - 为了让编译结果直接回写到 `examples/01/build/`，这里关闭了 `rootfs`
- `run-hello.toml`
  - 运行正常样例，预期 `status = ok`
- `run-timeout.toml`
  - 运行死循环，预期 `status = wall_time_limit_exceeded`
- `run-memory-limit.toml`
  - 运行爆内存样例，预期 `status = memory_limit_exceeded`
  - 需要宿主机提供可写 `cgroup v2`
- `run-danger-ptrace.toml`
  - 在 `default` seccomp 下执行 `ptrace` 样例，预期被拒绝
  - 样例会用非 `0` 退出码显式表示“seccomp 已拦截”，因此最终 `status = runtime_error`
- `run-danger-socket.toml`
  - 在 `strict` seccomp 下执行 `socket` 样例，预期被拒绝
  - 样例会用非 `0` 退出码显式表示“seccomp 已拦截”，因此最终 `status = runtime_error`
- `judge-jobs/cpp-isolated.json.in`
  - 用 rootfs + readonly inputs + `/output` 演示隔离编译 C++，再把 `outputs/main` 传给 run 阶段
- `judge-jobs/cpp-portable.json.in`
  - 不依赖 user namespace 的 C++ judge job 样例，适合先在当前宿主机走通完整链路
- `judge-jobs/java-isolated.json.in`
  - 用 rootfs + readonly inputs + `/output` 演示隔离编译 Java
  - 依赖宿主机或 Docker 环境提供 `javac` / `java`
- `judge-jobs/python-isolated.json.in`
  - 用 rootfs + readonly inputs + `/output` 演示 Python 语法检查和打包，再把输出交给 run/checker
- `judge-jobs/python-portable.json.in`
  - 不依赖 user namespace 的 Python judge job 样例，适合先在当前宿主机走通完整链路

## 使用方式

这个 `Makefile` 现在支持两种用法：

- 在仓库根目录运行 `make -f examples/01/Makefile ...`
- 先 `cd examples/01`，再直接运行 `make ...`

先校验配置：

```bash
make -f examples/01/Makefile sandbox-validate
```

再编译：

```bash
make -f examples/01/Makefile sandbox-compile
```

等价的底层命令是：

```bash
cargo run -p sandbox-cli -- compile \
  --config examples/01/configs/compile.toml \
  --source-dir . \
  --output-dir examples/01/build
```

运行正常样例：

```bash
make -f examples/01/Makefile sandbox-run-hello
```

运行超时样例：

```bash
make -f examples/01/Makefile sandbox-run-timeout
```

运行内存超限样例：

```bash
make -f examples/01/Makefile sandbox-run-memory-limit
```

运行 seccomp 拦截样例：

```bash
make -f examples/01/Makefile sandbox-run-danger-ptrace
make -f examples/01/Makefile sandbox-run-danger-socket
```

## 多阶段评测 Demo

先启动协议服务：

```bash
cargo run -p sandbox-cli -- --log-level warn serve --listen 127.0.0.1:3000
```

然后提交 C++ judge job：

```bash
make -f examples/01/Makefile sandbox-judge-cpp-portable
make -f examples/01/Makefile sandbox-judge-cpp
```

提交 Python judge job：

```bash
make -f examples/01/Makefile sandbox-judge-python-portable
make -f examples/01/Makefile sandbox-judge-python
```

提交 Java judge job：

```bash
make -f examples/01/Makefile sandbox-judge-java
```

这些 target 会：

- 把 `judge-jobs/*.json.in` 中的 `__REPO_ROOT__` 渲染成当前仓库绝对路径
- 调用 `POST /api/v1/judge-jobs`
- 直接走 `compile -> run -> checker` 链路

本机验证情况：

- C++ portable judge job：已本地验证可跑通
- Python portable judge job：已本地验证可跑通
- C++ / Python isolated judge job：模板已补齐，但当前宿主机 `user_namespace` 不可用，所以会被协议层明确拒绝
- Java judge job：样例和模板已补齐，但当前宿主机未安装 `javac` / `java`，建议在仓库提供的 Docker 环境里运行

推荐用法：

- 先在当前宿主机跑 `sandbox-judge-cpp-portable` 或 `sandbox-judge-python-portable`，确认评测链路本身没问题
- 再在支持 namespace 的 Linux 或 Docker dev 环境里跑 `sandbox-judge-cpp` / `sandbox-judge-python` / `sandbox-judge-java`

## 结果怎么看

所有 `sandbox-cli compile` / `sandbox-cli run` 的 stdout/stderr 和执行结果都会写进对应的 `artifact_dir`，默认在：

```text
.sandbox-runs/examples-01/
```

`sandbox-cli compile` 会额外输出：

- `source_dir`
- `output_dir`
- `outputs`

这样可以直接区分：

- 编译成功并拿到产物路径
- 编译器自身报错，`status = compilation_failed`
- 沙箱限额或隔离问题导致的失败

judge job 跑完后，你还可以直接查看 artifact：

```bash
curl -sS http://127.0.0.1:3000/api/v1/judge-jobs/examples-01-cpp-judge/artifacts
curl -sS "http://127.0.0.1:3000/api/v1/judge-jobs/examples-01-cpp-judge/artifacts/compile/file?path=outputs/main"
curl -sS "http://127.0.0.1:3000/api/v1/judge-jobs/examples-01-cpp-judge/artifacts/run/file?path=stdout.log"
```

如果你想先看宿主机能力再跑，可以用：

```bash
cargo run -p sandbox-cli -- inspect --config examples/01/configs/run-memory-limit.toml
```
