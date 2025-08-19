#include <fcntl.h>
#include <sys/stat.h>

int main() {
    mkfifo("/tmp/test_fifo", 0666);
    int fd = open("/tmp/test_fifo", O_WRONLY);
    char data[1024] = {0};
    for (int i = 0; i < 1024; i++) {
        write(fd, data, 1024);
    }
    close(fd);
    return 0;
}