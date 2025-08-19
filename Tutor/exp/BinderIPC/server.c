#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/android/binder.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main() {
    // TODO: 打开Binder设备文件（路径为/dev/binderfs/binder0）


    // TODO: 注册为Binder上下文管理器（使用BINDER_SET_CONTEXT_MGR命令）


    while (1) {
        char *buffer = malloc(4096);
        // TODO: 初始化binder_write_read结构体


        // TODO: 读取事务请求（使用BINDER_WRITE_READ命令）


        // TODO: 解析事务数据并打印事务代码

        free(buffer);
    }

    // TODO: 释放设备描述符
    return 0;
}