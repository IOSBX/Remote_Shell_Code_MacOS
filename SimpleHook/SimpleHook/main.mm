//
//  main.m
//  SimpleHook
//
//  Created by IosBX on 2025/12/3.
//

#import <Foundation/Foundation.h>

#include <stdio.h>
#include "SimpleHook.h"

// 保存原始函数的跳板地址
void *orig_func = NULL;

int main() {
    // 1. 获取目标进程 Task
    mach_port_t task = get_remote_task("TestCMD3");
    if (task == MACH_PORT_NULL) {
        printf("Error: Cannot find TestCMD3 task\n");
        return -1;
    }
    
    // 2. 获取目标进程基地址
    uint64_t header = get_remote_image_header(task);
    if (header == 0) {
        printf("Error: Cannot find image header\n");
        return -1;
    }
    
    printf("TestCMD3 Header: 0x%llx\n", header);
    
    // 3. 计算目标函数地址 (Header + 0x600)
    // 注意：0x600 可能不是 4字节对齐，但在用户要求下强制使用
    void *remote_target = (void*)(header + 0x600);
    printf("Target Address: %p\n", remote_target);

    // 4. 执行 Hook
    // 为了避免跨进程调用导致的崩溃，我们需要将 Hook 代码注入到远程进程
    // Shellcode: add w0, w0, w1; add w0, w0, #1; ret
    // 对应机器码 (Little Endian): 00 00 01 0b; 00 04 00 11; c0 03 5f d6
    uint8_t shellcode[] = {
        0x00, 0x00, 0x01, 0x0b, // add w0, w0, w1
        0x00, 0x04, 0x00, 0x11, // add w0, w0, #1
        0xc0, 0x03, 0x5f, 0xd6  // ret
    };
    
    void *remote_shellcode = inject_remote_code(task, shellcode, sizeof(shellcode));
    if (!remote_shellcode) {
        printf("Error: Failed to inject shellcode\n");
        return -1;
    }
    printf("Injected Shellcode at: %p\n", remote_shellcode);

    // 使用远程 Shellcode 地址进行 Hook
    int ret = simple_hook(remote_target, remote_shellcode, &orig_func, task);
    
    if (ret == 0) {
        printf("Hook Success! (Modified add to return a + b + 1)\n");
        printf("Please enter '1' in TestCMD3 to see '1 + 1 = 3'\n");
    } else {
        printf("Hook Failed: %d\n", ret);
    }
    
    return 0;
}
