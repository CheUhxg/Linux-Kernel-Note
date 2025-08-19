#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>

int main() {
    int fd = open("/tmp/test_fifo", O_RDONLY);
    char buffer[1024];
    struct timeval start, end;
    gettimeofday(&start, NULL);
    for (int i = 0; i < 1024; i++) {
        read(fd, buffer, 1024);
    }
    gettimeofday(&end, NULL);
    close(fd);
    // 计算时间差
    long seconds = end.tv_sec - start.tv_sec;
    long micros = end.tv_usec - start.tv_usec;
    if (micros < 0) {
        micros += 1000000;
        seconds--;
    }

    double elapsed = seconds * 1000.0 + micros / 1000.0;
    printf("[有名管道] 耗时: %.3f 毫秒\n", elapsed);
    return 0;
}