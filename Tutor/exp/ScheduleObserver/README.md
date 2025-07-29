# ScheduleObserver

* 添加一个内核模块，加载模块时创建多个线程，线程中会让出CPU并记录被调用的次数，卸载模块时会打印每个线程被执行的次数。

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

* 进入项目目录

```bash
cd practice_kern/ScheduleObserver
```

* 确认 [Makefile](Makefile) 中内核路径

```Makefile
# 目标内核的根目录（确认是否存在对应目录）
LINUX_KERNEL_PATH := /home/user/Kernel/v6.6/x86_64/
```

* 编译内核模块。

```bash
make
```

生成 `sched_observer.ko` 文件。

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
cd /tmp/share/practice_kern/ScheduleObserver
```

* 加载内核模块sched_observer，让出内核线程CPU并记录调用次数。

```bash
make load
```

* 输出示例：

```plaintext
sudo insmod sched_observer.ko
[  339.500002][ T7913] Initializing scheduler observer module...
```

* 卸载内核模块，打印每个线程被调用次数。

```bash
make unload
```

* 输出示例：

```plaintext
sudo rmmod sched_observer
[ 1266.246806][ T8007] Stopping threads...
[ 1266.279599][ T8007] Thread 0 (observer_0) schedule count: 114503991
[ 1266.279942][ T8007] Thread 1 (observer_1) schedule count: 6326901
[ 1266.280268][ T8007] Module unloaded.
```

## 实验要求

1. 修改线程0的调度方式，使得其被调用次数比其他线程多。

> 提示：请参考kernel/sched/core.c。