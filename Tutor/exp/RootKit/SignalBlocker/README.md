# SignalBlocker

* 添加一个内核模块，在内核中捕获发给malware的信号并记录。

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

* 加载内核模块注册内核处理函数。

```bash
make load
```

## 实验要求

* 请完善[signal_blocker.c](./signal_blocker.c)的TODO，使得执行`kill -SIGINT`后内核中有所记录。

```bash
root@kernel:~/SignalBlocker# kill -2 7906
[   69.457459][ T7875] signal_blocker: 拦截信号 2 到进程 'malware' (PID 7906)
```