# 操作系统内核分析及安全实验

## 会议

* 会议链接如下
> 会议主题：Linux内核培训
> 会议时间：2025/07/12 16:00-18:00 (GMT+08:00) 中国标准时间 - 北京
> 重复周期：2025/07/12-2025/08/23 16:00-18:00, 每周 (周六)
> #腾讯会议：625-1089-8614

* [录屏下载链接](https://pan.ruc.edu.cn/anyshare/zh-cn/dir/92A32D42BD0B4C918AD39FFF3F445A29)

## 环境

* [环境下载链接](https://pan.ruc.edu.cn/anyshare/zh-cn/dir/92A32D42BD0B4C918AD39FFF3F445A29)
  * VMWare虚拟机的两个虚拟化选项不是必选。
  * 宿主机用户user，密码abcd1234。
* [环境搭建文档](https://github.com/CheUhxg/Linux-Kernel-Note/blob/main/Tutor/exp/setup.md)
* [gdb操作文档](https://sourceware.org/gdb/current/onlinedocs/gdb#Commands)

## 章节实验

### ProcessShow

* 添加一个内核模块，加载模块时打印内核中所有进程的状态。

* [step-by-step](ProcessShow/README.md)

### ScheduleObserver

* 添加一个内核模块，加载模块时创建多个线程，线程中会让出CPU并记录被调用的次数，卸载模块时会打印每个线程被执行的次数。

* [step-by-step](ScheduleObserver/README.md)

### MemoryStatus

* 添加一个内核模块，加载模块时打印内核的物理内存状态。

* [step-by-step](MemoryStatus/README.md)

### TraverseVMA

* 添加一个内核模块，遍历所有进程的VMA。

* [step-by-step](./TraverseVMA//README.md)


### AddSyscall

* 添加一个内核模块，加载模块时添加一个系统调用。

* [step-by-step](./AddSyscall/README.md)

### AddMyEXT4

* 应用补丁，添加一个myext4文件系统。

* [step-by-step](./AddMyEXT4/README.md)

### CreateProc

* 添加一个内核模块，加载模块时在proc文件系统中添加一个目录和文件。

* [step-by-step](./CreateProc/README.md)

### IPCtest

* 课堂演示：测试所有进程间通信方式的性能。

* [step-by-step](./IPCtest/README.md)

### BinderIPC

* 两个用户态程序（客户端和服务端），通过binder进行IPC。

* [step-by-step](./BinderIPC/README.md)

### RaceCondition

* 添加两个系统调用，使得在不实施内核同步控制的情况下，用户调用系统调用，会经过不同的内核路径，从而触发共享变量的不一致。

* [step-by-step](./RaceCondition/README.md)

### VisitShared

* 添加一个内核模块，加载模块时通过中断处理函数、异常处理函数、可延迟函数访问一个自建的共享变量。

* [step-by-step](./VisitShared/README.md)

## RootKit

### HideProcess

* 添加一个内核模块，将指定进程从链表中摘除，使得ProcessShow无法检测到该进程。

* [step-by-step](RootKit/HideProcess/README.md)

### HideVMA

* 添加一个内核模块，将指定进程的VMA隐藏。

* [step-by-step](./RootKit/HideVMA/README.md)

### IDTHook

* 添加一个内核模块，注册一个键盘监控，打印每个键盘按键。

* [step-by-step](./RootKit/IDTHook/README.md)

### RedirectFile

* 添加一个内核模块，将指定进程打开的文件重定向到另一个文件（如`/etc/passwd`）。

* [step-by-step](./RootKit/RedirectFile/README.md)

### SignalBlocker

* 添加一个内核模块，在内核中捕获发给malware的信号并记录。

* [step-by-step](./RootKit/SignalBlocker/README.md)
