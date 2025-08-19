#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>  // 定义 uid_t
#include <linux/android/binder.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>

int main() {
    int binder_fd = open("/dev/binderfs/binder0", O_RDWR);
    if (binder_fd < 0) {
        perror("Failed to open binder device");
        return 1;
    }

    if (ioctl(binder_fd, BINDER_SET_CONTEXT_MGR, 0) < 0) {
        perror("Failed to set context manager");
        close(binder_fd);
        return 1;
    }

    while (1) {
        // 分配动态缓冲区
        char *buffer = malloc(4096);
        struct binder_write_read bwr = {
            .write_size = 0,
            .write_buffer = 0,
            .read_size = 4096,
            .read_buffer = (uintptr_t)buffer,
        };

        if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) < 0) {
            perror("Failed to read transaction");
            free(buffer);
            break;
        }

        if (bwr.read_consumed > 0) {
            struct binder_transaction_data *tr = (struct binder_transaction_data*)buffer;
            printf("Received transaction! Code: %d\n", tr->code);
            // 处理业务逻辑（此处示例仅打印）
        } else {
            // 无事务时降低 CPU 占用
            usleep(100000);
        }

        free(buffer);
    }

    close(binder_fd);
    return 0;
}