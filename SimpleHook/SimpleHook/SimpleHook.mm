//
//  SimpleHook.cpp
//  SimpleHook
//
//  Created by IosBX on 2025/12/3.
//

#include "SimpleHook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <libkern/OSCacheControl.h>
#import <Foundation/Foundation.h>

#if defined(__arm64__) || defined(__aarch64__)

// --- PAC 支持 ---
#if defined(__arm64e__)
#include <ptrauth.h>
#else
#define ptrauth_strip(x, key) ((void*)((uintptr_t)(x) & 0x0000000fffffffffull))
#define ptrauth_sign_unauthenticated(x, key, data) (x)
#endif


mach_port_t get_remote_task(const char *process_name) {
    pid_t pid = -1;
    size_t length = 0;
    static const int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int err = sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, NULL, &length, NULL, 0);
    if (err == -1) err = errno;
    if (err == 0) {
        struct kinfo_proc *procBuffer = (struct kinfo_proc *)malloc(length);
        if(procBuffer == NULL) return MACH_PORT_NULL;
        sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, procBuffer, &length, NULL, 0);
        int count = (int)(length / sizeof(struct kinfo_proc));
        for (int i = 0; i < count; ++i) {
            const char *procname = procBuffer[i].kp_proc.p_comm;
            NSString *procNameStr = [NSString stringWithFormat:@"%s",procname];
            if([procNameStr isEqualToString:[NSString stringWithUTF8String:process_name]]) {
                pid = procBuffer[i].kp_proc.p_pid;
                NSLog(@"[IosBX] Found %s pid:%d", process_name, pid);
                free(procBuffer);
                break;
            }
        }
        if (pid == -1 && procBuffer) free(procBuffer);
    }
    
    if (pid == -1) return MACH_PORT_NULL;
    
    mach_port_t task;
    kern_return_t kret = task_for_pid(mach_task_self(), pid, &task);
    if (kret == KERN_SUCCESS) {
        return task;
    } else {
        NSLog(@"[IosBX] task_for_pid failed: %d", kret);
        return MACH_PORT_NULL;
    }
}

// --- ARM64 绝对跳转指令序列 (16字节) ---
// ldr x17, #8      ; 从 PC+8 处加载地址到 x17
// br x17           ; 跳转到 x17
// .quad address    ; 64位地址
struct AbsJump {
    uint32_t ldr = 0x58000051; // ldr x17, .+8
    uint32_t br  = 0xd61f0220; // br x17
    uint64_t addr;
};

uint64_t get_remote_image_header(mach_port_t task) {
    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;
    uint32_t depth = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    
    while (1) {
        kern_return_t kr = mach_vm_region_recurse(task, &address, &size, &depth, (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;
        
        if (info.protection & VM_PROT_EXECUTE) {
            return address;
        }
        address += size;
    }
    return 0;
}

// --- 辅助：修改内存权限 ---
static int set_mem_exec(mach_port_t task, void *addr, size_t size) {
    if (task == MACH_PORT_NULL) task = mach_task_self();
    uintptr_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t len = ((uintptr_t)addr + size + page_size - 1) & ~(page_size - 1) - start;
    
    kern_return_t kr = mach_vm_protect(task, (mach_vm_address_t)start, len, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    return (kr == KERN_SUCCESS) ? 0 : -1;
}

// --- 核心：通过 Remap 技术覆盖代码页 ---
static int patch_code_via_remap(mach_port_t task, void *dest_addr, void *patch_data, size_t patch_len) {
    if (task == MACH_PORT_NULL) task = mach_task_self();
    size_t page_size = sysconf(_SC_PAGESIZE);
    vm_address_t page_start = (vm_address_t)dest_addr & ~(page_size - 1);
    int offset = (uintptr_t)dest_addr - page_start;
    
    // 1. 分配本地新页
    vm_address_t new_page = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &new_page, page_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return -1;
    
    // 2. 读取目标进程内存到本地新页
    mach_vm_size_t out_size = 0;
    kr = mach_vm_read_overwrite(task, (mach_vm_address_t)page_start, page_size, (mach_vm_address_t)new_page, &out_size);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), new_page, page_size);
        return -2;
    }
    
    // 3. 在本地新页应用补丁
    memcpy((void*)(new_page + offset), patch_data, patch_len);
    
    // 4. 设置本地新页为 R-X (remap 需要权限匹配)
    vm_protect(mach_task_self(), new_page, page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    
    // 5. Remap 覆盖目标进程
    vm_prot_t cur_prot, max_prot;
    kr = vm_remap(task, (vm_address_t*)&page_start, page_size, 0, VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED,
                  mach_task_self(), new_page, FALSE, &cur_prot, &max_prot, VM_INHERIT_COPY);
    
    // 6. 释放本地新页
    vm_deallocate(mach_task_self(), new_page, page_size);
    
    return (kr == KERN_SUCCESS) ? 0 : -3;
}

int simple_hook(void *target, void *replacement, void **original, mach_port_t target_task) {
    if (!target || !replacement) return -1;
    if (target_task == MACH_PORT_NULL) target_task = mach_task_self();

    // 1. 处理 PAC (简单 strip)
    void *real_target = ptrauth_strip(target, ptrauth_key_asia);
    size_t patch_size = sizeof(AbsJump); 
    size_t page_size = sysconf(_SC_PAGESIZE);

    // 2. 准备跳板 (Trampoline)
    // 必须在目标进程分配内存
    mach_vm_address_t trampoline = 0;
    kern_return_t kr = mach_vm_allocate(target_task, &trampoline, page_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return -1;

    // 3. 构建跳板内容 (在本地构建然后写入)
    uint8_t *local_trampoline = (uint8_t *)malloc(page_size);
    memset(local_trampoline, 0, page_size);
    
    // 3.1 读取原函数前16字节
    mach_vm_size_t read_size = 0;
    kr = mach_vm_read_overwrite(target_task, (mach_vm_address_t)real_target, patch_size, (mach_vm_address_t)local_trampoline, &read_size);
    if (kr != KERN_SUCCESS) {
        free(local_trampoline);
        return -4;
    }

    // 3.2 追加跳转回原函数+16
    AbsJump *jump_back = (AbsJump *)(local_trampoline + patch_size);
    AbsJump back_jump_inst;
    back_jump_inst.addr = (uint64_t)((uintptr_t)real_target + patch_size);
    *jump_back = back_jump_inst;
    
    // 3.3 写入跳板到目标进程
    kr = mach_vm_write(target_task, trampoline, (vm_offset_t)local_trampoline, page_size);
    free(local_trampoline);
    if (kr != KERN_SUCCESS) return -5;
    
    // 4. 设置跳板可执行
    set_mem_exec(target_task, (void*)trampoline, page_size);
    
    // 5. 生成 Patch 数据
    AbsJump hook_patch;
    hook_patch.addr = (uint64_t)replacement;
    
    // 6. 写入 Hook
    if (patch_code_via_remap(target_task, real_target, &hook_patch, patch_size) != 0) {
        return -6;
    }

    // 7. 返回跳板地址
    if (original) {
        *original = (void*)trampoline;
    }

    return 0;
}

void* inject_remote_code(mach_port_t task, const void *code, size_t size) {
    if (task == MACH_PORT_NULL || !code || size == 0) return NULL;
    
    mach_vm_address_t remote_addr = 0;
    kern_return_t kr = mach_vm_allocate(task, &remote_addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("mach_vm_allocate failed: %d\n", kr);
        return NULL;
    }
    
    kr = mach_vm_write(task, remote_addr, (vm_offset_t)code, (mach_msg_type_number_t)size);
    if (kr != KERN_SUCCESS) {
        printf("mach_vm_write failed: %d\n", kr);
        mach_vm_deallocate(task, remote_addr, size);
        return NULL;
    }
    
    kr = mach_vm_protect(task, remote_addr, size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        printf("mach_vm_protect failed: %d\n", kr);
        mach_vm_deallocate(task, remote_addr, size);
        return NULL;
    }
    
    return (void*)remote_addr;
}

#else
int simple_hook(void *target, void *replacement, void **original) { return -1; }
#endif
