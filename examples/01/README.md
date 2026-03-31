# examples/01

这个目录提供一组最小但完整的 C 语言沙箱样例，覆盖：

- 多文件正常程序编译与运行
- 死循环触发超时
- 爆内存触发 `memory.max`
- `ptrace` 与 `socket` 这类高风险 syscall 被 seccomp 拦截

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

如果你想先看宿主机能力再跑，可以用：

```bash
cargo run -p sandbox-cli -- inspect --config examples/01/configs/run-memory-limit.toml
```
