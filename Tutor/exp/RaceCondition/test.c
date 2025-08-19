#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>

#define SYS_CALL_454 454
#define SYS_CALL_455 455
#define SYS_CALL_456 456

void* thread_func_454(void *arg) {
    for (int i = 0; i < 100000; i++) {
        syscall(SYS_CALL_454);
    }
    return NULL;
}

void* thread_func_455(void *arg) {
    for (int i = 0; i < 100000; i++) {
        syscall(SYS_CALL_455);
    }
    return NULL;
}

int main() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_func_454, NULL);
    pthread_create(&t2, NULL, thread_func_455, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    int shared_counter = syscall(SYS_CALL_456);
    printf("Expected value: 0, Actual value: %d\n", shared_counter);
}