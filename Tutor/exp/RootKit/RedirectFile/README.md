# RedirectFile

* 添加一个内核模块，将指定进程打开的文件重定向到另一个文件（如`/etc/passwd`）。

## 实验运行

* 先在宿主机编译好内核模块。

```bash
make
```

* 之后进入客户机，执行：

```bash
rm malware
make malware
make run
```

* malware会给出指示，请执行对应的cat命令。

```bash
Malware process started. PID: 7909
Use: cat /proc/7909/maps to to check fd 3.
```

* 请记录加载内核模块之前的malware的fd3对应文件。

```bash
ll /proc/7909/fd/3
```

* 加载内核模块篡改malware的fd3，并再次记录fd3。

```bash
root@kernel:~/RedirectFile# make load
sudo insmod redirect_file.ko
[   38.116530][ T7915] redirect_file: loading out-of-tree module taints kernel.
[   38.116958][ T7915] redirect_file: module verification failed: signature and/or required key missl
[   38.117650][ T7915] hide_file模块正在加载...
[   38.117958][ T7915] 找到目标进程 "malware" (pid: 7909)
[   38.118307][ T7915] 找到目标文件: /home/user/secret_file (fd: 3)
[   38.118711][ T7915] 已将 fd 3 替换为 /etc/passwd
[   38.119010][ T7915] 文件隐藏成功。
root@kernel:~/RedirectFile# ll /proc/7909/fd/3
lrwx------ 1 root root 64 Apr 21 04:44 /proc/7909/fd/3 -> /etc/passwd
```

## 实验要求

* 请完善[redirect_file.c](./redirect_file.c)的TODO。
