# HideProcess

* 添加一个内核模块，将指定进程从链表中摘除，使得ProcessShow无法检测到该进程。

## 环境准备

* （可选）编译指定版本内核，实验中采用v6.6。

```bash
cd ~/Kernel
./compile v6.6 x86_64
```

* 拷贝仓库源码到宿主机的共享文件夹。

```bash
cd ~/Workdir/share
git clone http://10.10.21.30/linux-kernel/practice_kern.git
```

* 进入项目目录。

```bash
cd practice_kern/RootKit
```

* 确认[Makefile](Makefile)中路径是否正确。

```Makefile
# 目标内核的根目录（确认是否存在对应目录）
LINUX_KERNEL_PATH := /home/user/Kernel/v6.6/x86_64/
```

* 编译内核模块。

```bash
make
```

生成 `hide_process.ko` 文件。

## 实验运行

* 启动qemu运行编译好的内核。

```bash
./run v6.6 x86_64 focal
```

* 用户为user，无密码。

```bash
kernel login: user
```

> 接下来的操作都在客户机中。

* 进入客户机的共享文件夹中的实验目录。

```bash
cd /tmp/share/practice_kern/RootKit/HideProcess
```

* 编译运行malware。

```bash
make malware && make run
```

## 实验要求

* 如题（添加一个内核模块，将指定进程从链表中摘除，使得ProcessShow无法检测到该进程），ProcessShow参考[ProcessShow](../../ProcessShow/)。
* 实现效果如下，可以看到malware的进程消失了：

```bash
# before hide_process
[   42.624310][ T7891] PID: 7856   | State: INTERRUPTIBLE    | Command: systemd
[   42.624622][ T7891] PID: 7857   | State: UNKNOWN          | Command: (sd-pam)
[   42.624939][ T7891] PID: 7862   | State: INTERRUPTIBLE    | Command: bash
[   42.625241][ T7891] PID: 7882   | State: UNKNOWN          | Command: malware
[   42.625553][ T7891] PID: 7888   | State: INTERRUPTIBLE    | Command: make
[   42.625853][ T7891] PID: 7890   | State: INTERRUPTIBLE    | Command: sudo
[   42.626156][ T7891] PID: 7891   | State: RUNNING          | Command: insmod

# after hide_process
[  102.624758][ T7910] PID: 7856   | State: INTERRUPTIBLE    | Command: systemd
[  102.625099][ T7910] PID: 7857   | State: UNKNOWN          | Command: (sd-pam)
[  102.625444][ T7910] PID: 7862   | State: INTERRUPTIBLE    | Command: bash
[  102.625804][ T7910] PID: 7907   | State: INTERRUPTIBLE    | Command: make
[  102.626134][ T7910] PID: 7909   | State: INTERRUPTIBLE    | Command: sudo
[  102.626463][ T7910] PID: 7910   | State: RUNNING          | Command: insmod
```