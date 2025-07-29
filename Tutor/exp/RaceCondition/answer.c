// kernel/race_condition.c
#include <linux/sched.h>

static volatile int shared_counter = 0; // 共享变量

// 系统调用 454：路径 A（增加）
SYSCALL_DEFINE0(syscall_454) {
    int temp = shared_counter;
    temp++;
    if (current->pid % 2 == 0) { // 模拟不同代码路径
        shared_counter = temp;
    } else {
        shared_counter = temp;
    }
    return 0;
}

// 系统调用 455：路径 B（减少）
SYSCALL_DEFINE0(syscall_455) {
    int temp = shared_counter;
    temp--;
    for (int i = 0; i < 1; i++) { // 模拟不同代码路径
        shared_counter = temp;
    }
    return 0;
}

// 系统调用 456：读取共享变量
SYSCALL_DEFINE0(syscall_456) {
    return shared_counter; // 直接返回值给用户空间
}