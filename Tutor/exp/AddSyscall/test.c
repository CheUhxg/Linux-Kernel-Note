#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MY_SYSCALL_NR 335

int main() {
    long pid = syscall(MY_SYSCALL_NR);
    
    printf("Syscall returned PID: %ld\n", pid);
    printf("Compare with getpid(): %d\n", getpid());
    
    return 0;
}