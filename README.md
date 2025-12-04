# SimpleHook

SimpleHook 是一个用于 macOS (iOS?) 的轻量级远程代码注入与 Inline Hook 库。它演示了如何获取远程进程任务端口、注入代码以及通过 `vm_remap` 技术修改远程进程内存以实现函数挂钩。

## 功能特性

- **获取远程 Task**: 通过进程名获取 mach task port (`get_remote_task`)。
- **获取基地址**: 获取远程进程的主二进制镜像头部地址 (`get_remote_image_header`)。
- **代码注入**: 将 Shellcode 或数据注入到远程进程内存 (`inject_remote_code`)。
- **Inline Hook**: 支持跨进程的 Inline Hook，使用 `vm_remap` 技术绕过部分内存写保护，自动生成跳板 (`simple_hook`)。

## 环境要求

- macOS 或 iOS (iOS 可能需要修改代码或签名配置)
- ARM64 架构 (代码针对 arm64 编写)
- 可能需要相应的 Entitlements (如 `com.apple.security.get-task-allow`, `task_for_pid-allow`) 以获取远程进程的 Task Port。

## API 概览

```c
// 获取指定进程名的 Task
mach_port_t get_remote_task(const char *process_name);

// 获取指定 Task 的主二进制 Image Header 地址
uint64_t get_remote_image_header(mach_port_t task);

// 简单的 Inline Hook 函数
// target: 目标函数地址
// replacement: 你的 Hook 函数地址 (或注入的 Shellcode 地址)
// original: 用于接收原函数的跳板地址
// target_task: 目标进程 Task
int simple_hook(void *target, void *replacement, void **original, mach_port_t target_task);

// 注入代码到远程进程
void* inject_remote_code(mach_port_t task, const void *code, size_t size);
```

## 使用示例

参见 `main.mm`。该示例演示了如何 Hook 另一个名为 "TestCMD3" 的进程。

1. 查找名为 "TestCMD3" 的进程。
2. 计算目标函数地址 (基地址 + 0x600)。
3. 注入一段简单的 Shellcode (实现 `a + b + 1` 的逻辑)。
4. Hook 目标函数跳转到注入的 Shellcode。

```c
// 核心逻辑示例
mach_port_t task = get_remote_task("TestCMD3");
uint64_t header = get_remote_image_header(task);
void *remote_target = (void*)(header + 0x600);

// Shellcode: add w0, w0, w1; add w0, w0, #1; ret
uint8_t shellcode[] = { ... };
void *remote_shellcode = inject_remote_code(task, shellcode, sizeof(shellcode));

// 执行 Hook
simple_hook(remote_target, remote_shellcode, &orig_func, task);
```

## 原理简述

1. **task_for_pid**: 获取目标进程的控制权。
2. **vm_remap**: `simple_hook` 使用 `vm_remap` 重新映射内存页。这是一种常用的技术，用于在无法直接写入（如代码段只读）的情况下修改内存。它创建一个新的可写页，修改后再将其映射回目标地址。
3. **Trampoline**: Hook 会自动创建一个跳板（Trampoline），保存被覆盖的指令，并跳转回原函数，从而允许调用原始实现。

## 免责声明

本项目仅供安全研究和教育目的使用。请勿用于恶意用途。
