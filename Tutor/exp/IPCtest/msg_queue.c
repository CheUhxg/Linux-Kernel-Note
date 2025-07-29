#include <mqueue.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    mqd_t mq = mq_open("/test_mq", O_CREAT | O_RDWR, 0666, NULL);
    if (fork() == 0) {
        // 子进程：读消息
        char buffer[8192];
        struct timeval start, end;
        gettimeofday(&start, NULL);
        for (int i = 0; i < 10; i++) {
            mq_receive(mq, buffer, 8192, NULL);
        }
        gettimeofday(&end, NULL);
        // 计算时间差
        // 在子进程的最后添加：
        long seconds = end.tv_sec - start.tv_sec;
        long useconds = end.tv_usec - start.tv_usec;
        double total_time = (seconds * 1000000.0 + useconds) / 1000000.0;
        printf("[消息队列] 吞吐量: %.2f KB/s\n", 8 * 10 / total_time);
    } else {
        // 父进程：发消息
        char data[8192] = {0};
        for (int i = 0; i < 10; i++) {
            mq_send(mq, data, 8192, 0);
        }
        wait(NULL);
        mq_close(mq);
        mq_unlink("/test_mq");
    }
    return 0;
}