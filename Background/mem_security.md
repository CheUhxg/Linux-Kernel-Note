# 简介

根据内存安全发展历程，按照时间顺序，总结攻击方式以及对应的防御策略。

# 攻击以及防御策略

## 缓冲区溢出

缓冲区溢出是一种软件编码错误或漏洞，黑客可以利用它未经授权访问系统。它是最著名的软件安全漏洞之一，而且相当普遍。这在一定程度上是因为缓冲区溢出可能以各种方式发生，而用于防止溢出的技术往往容易出错。

> 缓冲区溢出包括栈溢出和堆溢出。

### 栈溢出

栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而**导致与其相邻的栈中的变量的值被改变**。

发生栈溢出的基本前提
* 程序向栈上写入数据。
* 写入的数据大小超过分配的大小。

通过精心设计溢出数据，可以实现rip劫持。详细参考[栈溢出](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stackoverflow-basic/#_3)。

### 堆溢出

堆溢出是指**程序向某个堆块中写入的字节数超过了堆块本身可使用的字节数**，因而导致了数据溢出，并**覆盖到物理相邻的高地址的下一个堆块**。
* *是可使用而不是用户申请的字节数*，因为堆管理器会对用户所申请的字节数进行调整，这也导致可利用的字节数都不小于用户申请的字节数。

堆溢出漏洞发生的基本前提
* 程序向堆上写入数据。
* 写入的数据大小超过可使用字节数。

与栈溢出所不同的是，堆上并不存在返回地址等可以让攻击者直接控制执行流程的数据，因此我们一般无法直接通过堆溢出来控制rip。

利用堆溢出的策略是
1. **覆盖与其物理相邻的下一个chunk的内容**：
   * prev_size
   * size：主要有三个比特位，以及该堆块真正的大小。
     * NON_MAIN_ARENA
     * IS_MAPPED
     * PREV_INUSE
     * the True chunk size
   * chunk content
2. 利用堆中的机制（如unlink等 ）来**实现任意地址写入或控制堆块中的内容**等效果，从而来控制程序的执行流，参考[堆溢出](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/heapoverflow-basic/#_3)。

### 防御策略：栈破坏检查

针对栈溢出设计的栈破坏检查，可以防止栈溢出漏洞。

栈金丝雀(Stack Canaries)是放置在堆栈上的一个秘密值，它在每次程序启动时都会更改。在函数返回之前，检查堆栈指示器，如果它被修改了，程序立即退出。

栈金丝雀是由编译器生成的，位于Buffer和SFP中间。

![](https://images.contentstack.io/v3/assets/blt36c2e63521272fdc/blt5f070f8052db15bc/601c8cf44b8030688c37b8b9/StackCanaries_Fig3.png)

# 缓解机制

## UAO

> 作者：Vitaly Nikolenko  
> 发布时间：2020 年 9 月 4 日 18:10  

本文介绍 Linux/Android 内核中 UAO（User Access Override）的实现细节，并演示其如何抵御经典的 *addr_limit 覆盖* 内核利用技术。  
当前市面主流 Android 设备已基于 ARMv8.2 架构，UAO 正是 ARMv8.2 引入的特性：它允许未特权的 load/store（`ldtr*`/`sttr*`）在 EL1 下表现得像特权指令 `ldr*`/`str*`。

| 指令 | 权限级别 | 检查规则 | 在 EL1 下访问用户空间 | 在 EL1 下访问内核空间 |
|---|---|---|---|---|
| `str` / `ldr` | **特权** | 只看 PAN 开关 | **必须关 PAN** 才能写用户空间 | 始终 OK |
| `sttr` / `ldtr` | **非特权** | 永远做权限检查 | **UAO=0 时放行**；UAO=1 时报错 | **UAO=0 时报错**；UAO=1 时放行 |

| 场景 | 宏展开成 | PAN 状态 | UAO 位 | 结果 |
|---|---|---|---|---|
| **老内核无 UAO** | `str/ldr` | 先关后开 | 不存在 | 正常读写用户空间 |
| **新内核 + addr_limit ≠ -1** | `sttr/ldtr` | 不用关 | UAO=0 | 正常读写用户空间 |
| **新内核 + addr_limit = -1** | `sttr/ldtr` | 不用关 | UAO=1 | **读写用户空间立刻异常**，攻击失败 |

### 无 UAO 时的做法  
在没有 UAO 的旧系统里，内核访问用户空间需临时关闭 PAN（Privileged Access Never）：

```asm
__arch_copy_to_user:
    ...
    uaccess_enable_not_uao x3, x4, x5   ; 关 PAN
    ; 使用特权 ldr/str 拷贝数据
    uaccess_disable_not_uao x3, x4      ; 开 PAN
```

### 支持 UAO 时的做法  
当 CPU 支持 UAO，`uaccess_enable/disable_not_uao` 宏被替换成空操作（`nop`）。此时所有访问用户空间的宏指令会走 `uao_user_alternative`：

```asm
    uao_user_alternative  strb, sttrb, tmp, addr, #1
```

- 若 **无 UAO** → 使用特权 `strb`  
- 若 **有 UAO** → 使用非特权 `sttrb`，并在 UAO 位=1 时表现为特权访问

### 上下文切换中的处理  
内核每次任务切换都会调用 `uao_thread_switch`：

```c
void uao_thread_switch(struct task_struct *next)
{
    if (task_thread_info(next)->addr_limit == KERNEL_DS)
        SET_PSTATE_UAO(1);   /* 打开 UAO */
    else
        SET_PSTATE_UAO(0);   /* 关闭 UAO */
}
```

- 当 `addr_limit == KERNEL_DS`（即 0xffff ffff ffff ffff）  
  → 打开 UAO，使 `ldtr* / sttr*` 产生 fault，**防止误访问用户空间**  
- 当 `addr_limit != KERNEL_DS`  
  → 关闭 UAO，`ldtr* / sttr*` 以 EL0 行为执行，**正常完成 copy_to_user / copy_from_user**

### addr_limit覆盖攻击  
攻击者把当前任务的 `addr_limit` 设为 `KERNEL_DS`（-1），随后利用 `pipe()` 实现任意内核读写：

```c
pipe(pipefds);
/* 任意读：把内核地址写入 pipe，再从 pipe 读出 */
write(pipefds[1], kernel_addr, 8);
read(pipefds[0], &val, 8);
```

UAO 下的结果：
- **copy_from_user**（`write` 路径）：  
  `ldtr*` 读取内核地址 → 失败，返回 0 字节，不产生异常。  
- **copy_to_user**（`read` 路径）：  
  `sttr*` 写入用户空间 → 因 UAO=1 触发页错误，直接失败。  

因此整个利用链路被阻断。

### 绕过

若攻击者把 `addr_limit` 改成 **-2** 而非 -1，`uao_thread_switch` 不会打开 UAO，`ldtr* / sttr*` 将以 EL0 权限运行，理论上仍可继续利用。但此时内核无法直接触及用户空间，需要额外技巧（例如先构造用户空间映射等）。

# 参考

* [栈溢出](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stackoverflow-basic/)
* [堆溢出](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/heapoverflow-basic/)
* [stack canary](https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/)
* [UAO(User Access Override)](https://duasynt.com/blog/android-uao-kernel-expl-mitigation)