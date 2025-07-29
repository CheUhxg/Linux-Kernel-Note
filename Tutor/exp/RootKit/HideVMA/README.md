# HideVMA

* 添加一个内核模块，将指定进程的VMA隐藏。

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
Malware process started. PID: 7936
Use: cat /proc/7936/maps to check VMA before and after loading the kernel module.
```

* 请记录加载内核模块之前的malware的maps。

```bash
cat /proc/7936/maps > ori
```

* 加载内核模块篡改malware的maps，并再次记录maps。

```bash
make load
cat /proc/7936/maps > new
```

## 实验要求

* 请完善[hide_vma.c](./hide_vma.c)的TODO，使得ori和new文件有不同（说明有vma被隐藏）。

```bash
root@kernel:~/HideVMA# diff ori new
2d1
< 564dcf334000-564dcf335000 r-xp 00001000 08:00 28519                      /root/HideVMA/malware
```