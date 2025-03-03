# 一、引言

攻击者需要手动查明释放对象（即漏洞对象）出现的时间帧，以便将数据喷洒到其区域，并据此修改其内容。为了确保操作系统内核的安全执行会受到喷洒数据的影响，他还需要利用自己的专业知识，根据释放对象的大小以及堆分配器的类型，手动调整系统调用和相应的参数。

因为UAF漏洞的利用需要对漏洞对象进行空间和时间控制，在这些约束条件下，微小的上下文变化通常不利于可利用性探索。

FUZE，一个评估内核UAF漏洞可利用性的攻击框架，利用内核fuzzing来探索各种系统调用，从而改变内核panic的上下文。在每个环境下，每一个不同的内核panic，FUZE进一步执行符号执行的目标是追踪潜在的有用的原语利用。

# 二、背景和挑战

> 安全分析人员需要确定*导致悬浮指针出现*以及*解引用该指针*的系统调用

问题1：为什么不考虑free点和use点在同一个系统调用的情况？

堆喷的目标是**接管释放的对象**，从而利用所喷洒的数据将系统的控制流重定向到未经授权的操作，例如权限提升或关键数据泄漏。安全分析人员还需要根据PoC程序的语义仔细计算所喷洒数据的内容，从而**调整**为执行堆喷而选择的系统调用的**参数**。

意外的写原语只给予分析人员将不可管理的数据(即新对象的地址)写入Linux内核中不可管理的堆地址的特权。换句话说，这意味着分析人员不能利用意外的写操作来操作指令指针rip，从而执行控制流劫持，也不能利用它来操作Linux内核中的关键数据，从而实现权限提升。

# 三、概述

由于系统调用sendmsg()具有*解引用双链表中新添加的对象中的数据*的能力，当意外的释放操作发生并出现悬浮指针时，它具有在原始PoC中定义的系统调用之前解引用悬浮指针的能力，从而改变内核panic的方式。

我们提出了一种技术方法来促进PoC程序的上下文变化。我们将它们与下面几节将介绍的其他技术一起命名为FUZE，这是一个利用框架。该框架背后的设计理念是，**上下文变化可以促进识别利用原语**，有了上下文变化，可以潜在地加快制作工作利用，并可以显著升级内核UAF漏洞的可利用性。

> FUZE的最终目标不是 `<u>`自动生成一个可运行利用，而是激发安全分析人员编写一个可运行利用的能力 `</u>`。

问题2：FUZE最终输出不是一个EXP吗？

我们设计了FUZE：首先运行PoC程序，并使用现成的ASAN进行分析。随着动态追踪方法的便利，FUZE可以识别与漏洞对象有关的关键信息，以及连续利用所需的时间窗口。

1. 从技术上讲，我们设计并开发了一种上下文中fuzzing方法，它自动探索 `<u>`确认过的时间窗口内的内核代码空间 `</u>`，从而确定可能导致内核panic的系统调用(和相应的参数)。
2. 一个新的上下文(即新的内核恐慌)不一定能帮助分析人员创建一个有效的漏洞。我们进一步设计了FUZE来自动评估每一个新的上下文。
   - 我们将释放对象的每个字节设置为一个符号值，然后在每个上下文中实施符号执行。
   - 我们**在悬空指针解引用之后**立即执行符号执行。可以防止发生路径爆炸。

# 四、设计

## 信息提取

1. KASAN信息。
2. ftrace跟踪。
3. 关联1和2。

## 内核fuzz

我们必须**在出现悬浮指针之后启动内核模糊测试**，同时，**确保模糊测试不受原始PoC中指定的指针解引用的干扰**。通过使用KASAN和动态跟踪提取的信息轻松实现。

下一步是消除 `<u>`原始PoC中指定的、能够解引用悬浮指针的系统调用 `</u>`的干预。我们将PoC程序包装为一个独立的函数，然后对该函数进行修饰，使其具有触发释放操作的能力，但避免触及悬空指针解引用的位置。
* 单线程：在两个系统调用之间插入一个返回语句来检测PoC程序。
* 多线程：在迭代末尾插入系统调用ioctl。

我们需要在解引用悬浮指针之前终止PoC的执行。通过向内核模块提供内存地址(内核模块监视内核内存中的分配和释放操作)，我们可以增强内核模块的能力，使其能够精确定位目标对象的产生，并提醒系统调用ioctl**将包装函数的执行重定向到连续的内核fuzzing处理中**。

## 符号执行

我们需要定位悬空指针解引用的位置，暂停内核执行并传递运行中的上下文给符号执行。我们在解引用之前设置一个断点，如果被释放的对象没有被观测到，我们强制内核继续它的执行。否则，我们暂停内核执行，并将其作为连续符号执行的初始设置。

我们为被释放对象的每一个字节创建符号化的值。之后，我们符号化地恢复了内核的执行，并探索可能对漏洞探索有用的机器状态。

**原语指定**。我们定义2个原语类型——*控制流劫持*和*非法写入*。它们在一定假设下通常是执行利用的必要条件。

**原语评估**。为了评估原语的利用价值，我们采用以下方法：

1. **控制流劫持评估**：假设攻击者通过控制流劫持原语进行利用。在启用了SMEP的情况下，我们检查控制流是否可以被重定向到内核代码片段（如`xchg eax, esp; ret`），然后通过设置`eax`寄存器指向有效的用户空间地址，控制堆栈跳转。通过符号执行，我们验证目标地址是否可以指向该内核代码片段，并进一步检查`eax`的值是否在有效的内存范围内。

2. **非法写入评估**：对于绕过SMEP的另一种方法，我们评估是否存在非法写入原语，该原语通过操纵被释放对象的元数据误导内存管理，将一个新对象分配到用户空间。我们检查写入源是否有效，且目标地址是否指向已释放对象的元数据，判断是否有能力将数据修改为用户空间地址。

3. **SMAP绕过评估**：为了绕过SMAP，我们检查攻击者是否能通过修改寄存器`rdi`的值（例如设置为0x6f0）并将控制流重定向到`native_write_cr4()`函数，禁用SMAP并进行控制流劫持。我们使用符号执行工具验证`rdi`值的正确性，并确认目标地址是否能指向`native_write_cr4()`。

应用的符号执行自然为FUZE提供了计算需要喷射到被释放对象的数据的能力。因此，在这项工作中，我们利用现成的约束解算器（即SMT）来计算所有符号变量的值，而符号探索则达到可利用的机器状态。