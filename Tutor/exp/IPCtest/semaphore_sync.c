#include <semaphore.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */

int main() {
    sem_t *sem = sem_open("/test_sem", O_CREAT, 0666, 0);
    if (fork() == 0) {
        // 子进程：post信号量
        for (int i = 0; i < 1024; i++) {
            sem_post(sem);
        }
    } else {
        // 父进程：wait信号量并计时
        struct timeval start, end;
        gettimeofday(&start, NULL);
        for (int i = 0; i < 1024; i++) {
            sem_wait(sem);
        }
        gettimeofday(&end, NULL);
        // 计算时间差
        double avg_latency = ((end.tv_sec - start.tv_sec) * 1000000.0 + 
        (end.tv_usec - start.tv_usec)) / 2048.0;
        printf("[信号量] 平均延迟: %.3f 微秒/次\n", avg_latency);
        sem_close(sem);
        sem_unlink("/test_sem");
    }
    return 0;
}