#include <sys/mman.h>
#include <semaphore.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */

int main() {
    // 创建共享内存和信号量
    int shm_fd = shm_open("/test_shm", O_CREAT | O_RDWR, 0666);
    ftruncate(shm_fd, 1024);
    char *shm_ptr = mmap(NULL, 1024, PROT_READ|PROT_WRITE, MAP_SHARED, shm_fd, 0);
    
    sem_t *sem_w = sem_open("/test_sem_w", O_CREAT, 0666, 1);
    sem_t *sem_r = sem_open("/test_sem_r", O_CREAT, 0666, 0);
    
    if (fork() == 0) {
        // 子进程：读数据
        for (int i = 0; i < 1024; i++) {
            sem_wait(sem_r);
            sem_post(sem_w);
        }
    } else {
        // 父进程：写数据
        struct timeval start, end;
        gettimeofday(&start, NULL);
        for (int i = 0; i < 1024; i++) {
            sem_wait(sem_w);
            sem_post(sem_r);
        }
        gettimeofday(&end, NULL);
        // 计算时间差
        double elapsed = (end.tv_sec - start.tv_sec) * 1000.0 + 
        (end.tv_usec - start.tv_usec) / 1000.0;
        printf("[共享内存] 同步耗时: %.3f 毫秒\n", elapsed);
        wait(NULL);
    }
    // 清理资源
    sem_close(sem_w); sem_unlink("/test_sem_w");
    sem_close(sem_r); sem_unlink("/test_sem_r");
    shm_unlink("/test_shm");
    return 0;
}