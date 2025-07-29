obj-m += add_syscall.o

TEST_PROG = test_syscall
CC = gcc
CFLAGS = -Wall -O2

# 内核构建路径（根据实际情况修改）
LINUX_KERNEL_PATH := /home/user/Kernel/v5.6/x86_64/

# 当前工作目录
CURRENT_PATH := $(shell pwd)

all: module $(TEST_PROG)

module:
	@echo "Building kernel module..."
	@make -s -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules

$(TEST_PROG): test.c
	@echo "Building userspace test program..."
	@$(CC) $(CFLAGS) -o $@ $^

clean:
	@make -s -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean
	@rm -f $(TEST_PROG)

load:
	@sudo insmod add_syscall.ko

unload:
	@sudo rmmod add_syscall

run: $(TEST_PROG)
	@sudo dmesg -C
	@-sudo rmmod add_syscall 2>/dev/null || true
	@sudo insmod add_syscall.ko
	@./$(TEST_PROG)
	@sudo rmmod add_syscall

.PHONY: all module clean load unload run