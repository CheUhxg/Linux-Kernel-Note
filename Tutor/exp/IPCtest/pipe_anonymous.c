#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    int fd[2];
    pipe(fd);
    if (fork() == 0) {
        // 子进程：读数据
        close(fd[1]);
        char buffer[1024];
        struct timeval start, end;
        gettimeofday(&start, NULL);
        for (int i = 0; i < 1024; i++) {
            read(fd[0], buffer, 1024);
        }
        gettimeofday(&end, NULL);
        // 计算时间差
        long seconds = end.tv_sec - start.tv_sec;
        long micros = end.tv_usec - start.tv_usec;
        if (micros < 0) {
            micros += 1000000;
            seconds--;
        }
        double elapsed = seconds * 1000.0 + micros / 1000.0;
        printf("[匿名管道] 耗时: %.3f 毫秒\n", elapsed);
        close(fd[0]);
    } else {
        // 父进程：写数据
        close(fd[0]);
        char data[1024] = {0};
        for (int i = 0; i < 1024; i++) {
            write(fd[1], data, 1024);
        }
        close(fd[1]);
        wait(NULL);
    }
    return 0;
}