# Malicious Sample Catalog

`crates/sandbox-testkit` 现在提供了一组可复用的恶意/误用样例，供 supervisor 回归测试、CI 回归和本地排障复用。

## 当前样例

- `host_filesystem_escape`
  - 目标：尝试读取 chroot 之外的宿主机文件
  - 预期防线：rootfs / chroot 可见性隔离
- `proc_info_leak_probe`
  - 目标：尝试通过 `/proc` 观察超出预期的进程信息
  - 预期防线：PID namespace 内的最小 `/proc` 挂载
- `readonly_input_tamper`
  - 目标：尝试改写只读输入文件
  - 预期防线：readonly bind mount 策略
- `strict_socket_creation`
  - 目标：在 `strict` seccomp profile 下创建网络 socket
  - 预期防线：`strict` profile 的 socket deny 规则
- `default_ptrace_probe`
  - 目标：在默认 seccomp profile 下调用 `ptrace`
  - 预期防线：默认 profile 的 `ptrace` deny 规则
- `checker_uds_probe`
  - 目标：尝试连接错误暴露在共享输出目录中的 checker Unix domain socket
  - 预期防线：checker 不应与用户程序在同一运行阶段混跑，也不应把 UDS 暴露到共享目录

## 使用位置

- `sandbox-supervisor` 的安全回归测试会直接消费这些样例
- `scripts/run_regression_suite.sh` 会运行相关 workspace 测试
- `scripts/run_stress_suite.sh` 会配合压力场景重复执行 supervisor 主路径

## 后续扩展方向

- 输出洪泛 / 磁盘打满样例
- 编译阶段隔离样例
- 更强的 `/proc` 与管理进程信息泄漏样例
