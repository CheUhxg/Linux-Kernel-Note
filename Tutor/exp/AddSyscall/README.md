# AddSyscall

* 添加一个内核模块，加载模块时添加一个系统调用。

## 实验要求

1. 通过修改源码添加一个系统调用。
2. 完善内核模块[add_syscall.c](./add_syscall.c)。

* 编译执行[test.c](./test.c)，该程序调用自定义系统调用，比较返回值是否与getpid返回相同的pid。

* 执行命令顺序如下：

```bash
make load
make test_syscall
./test_syscall
```

* 期望输出如下：

```bash
user@kernel:/tmp/share/practice_kern/AddSyscall$ ./test_syscall 
Syscall returned PID: 349
Compare with getpid(): 349
```