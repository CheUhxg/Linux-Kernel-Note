#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/android/binder.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main() {
    int binder_fd = open("/dev/binderfs/binder0", O_RDWR);
    if (binder_fd < 0) {
        perror("Failed to open binder device");
        return 1;
    }

    // 1. 构造 binder_transaction_data
    struct binder_transaction_data tr = {
        .target.handle = 0,          // 目标句柄（0 表示 ServiceManager）
        .code = 1,                    // 自定义事务代码
        .flags = TF_ACCEPT_FDS,       // 事务标志
        .data_size = strlen("Hello Binder!") + 1,  // 数据长度（含终止符）
        .data.ptr.buffer = (uintptr_t)"Hello Binder!",  // 数据指针
        .offsets_size = 0,            // 无嵌套对象
    };

    // 2. 构造 Binder 命令序列
    //    - BC_TRANSACTION 命令码（32 位）
    //    - 后跟 binder_transaction_data 结构体
    uint32_t cmd = BC_TRANSACTION;    // 命令码
    char write_buf[sizeof(cmd) + sizeof(tr)];
    memcpy(write_buf, &cmd, sizeof(cmd));                // 写入 BC_TRANSACTION
    memcpy(write_buf + sizeof(cmd), &tr, sizeof(tr));    // 写入事务数据

    // 3. 设置 binder_write_read 结构体
    struct binder_write_read bwr = {
        .write_size = sizeof(write_buf),      // 写入缓冲区总大小
        .write_buffer = (uintptr_t)write_buf, // 写入缓冲区指针
        .read_size = 0,                       // 不读取返回数据
        .read_buffer = 0,
    };

    // 4. 提交事务
    if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) < 0) {
        perror("Failed to send transaction");
        close(binder_fd);
        return 1;
    }

    printf("Transaction sent!\n");
    close(binder_fd);
    return 0;
}