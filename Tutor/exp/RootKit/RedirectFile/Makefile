obj-m += redirect_file.o

# 当前模块路径
CURRENT_PATH := $(shell pwd)

# 目标内核源码路径
LINUX_KERNEL_PATH := /home/user/Kernel/v6.6/x86_64/

# 默认目标：同时构建内核模块和用户态程序
all: redirect_file.ko malware

# 编译用户态伪装程序
malware: malware.c
	$(CC) -o $@ $^

# 编译内核模块
redirect_file.ko: redirect_file.c
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules

# 清理所有构建产物
clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean
	$(RM) -f malware

# 加载和卸载模块
load:
	sudo insmod redirect_file.ko

unload:
	sudo rmmod redirect_file

# 启动用户程序
run: malware
	sudo ./malware &
