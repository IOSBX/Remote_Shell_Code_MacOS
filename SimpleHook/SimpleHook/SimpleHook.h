//
//  SimpleHook.h
//  SimpleHook
//
//  Created by IosBX on 2025/12/3.
//

#pragma once

#include <stdint.h>
#include <mach/mach_types.h>

// 获取指定进程名的 Task
mach_port_t get_remote_task(const char *process_name);

// 获取指定 Task 的主二进制 Image Header 地址
uint64_t get_remote_image_header(mach_port_t task);

// 简单的 Inline Hook 函数
// target: 目标函数地址
// replacement: 你的 Hook 函数地址
// original: 用于接收原函数的跳板地址 (调用它即调用原函数)
// target_task: 目标进程 Task (如果为 MACH_PORT_NULL 则为当前进程)
// 返回值: 0 成功, <0 失败
int simple_hook(void *target, void *replacement, void **original, mach_port_t target_task = MACH_PORT_NULL);

// 注入代码到远程进程
// task: 目标进程 Task
// code: 本地代码数据
// size: 代码大小
// 返回值: 远程地址，失败返回 NULL
void* inject_remote_code(mach_port_t task, const void *code, size_t size);
