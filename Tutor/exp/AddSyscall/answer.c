#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>

#define __NR_syscall 335    // 保持原系统调用号
unsigned long *sys_call_table;

unsigned int clear_and_return_cr0(void);
void setback_cr0(unsigned int val);
static int sys_mycall(void); // 保持原函数名

int orig_cr0;               // 保持原变量名
static int (*anything_saved)(void); // 保持原指针类型

/* 完全保留原CR0操作方式 */
unsigned int clear_and_return_cr0(void)
{
    unsigned int cr0 = 0;
    unsigned int ret;
    asm volatile ("movq %%cr0, %%rax" : "=a"(cr0));
    ret = cr0;
    cr0 &= 0xfffeffff;
    asm volatile ("movq %%rax, %%cr0" :: "a"(cr0));
    return ret;
}

void setback_cr0(unsigned int val)
{
    asm volatile ("movq %%rax, %%cr0" :: "a"(val));
}

static int sys_mycall(void)
{
    return task_tgid_vnr(current);
}

/* 完全保留原初始化函数结构 */
static int __init init_addsyscall(void)
{
    // TODO: get sys_call_table 
    sys_call_table = (unsigned long *)0xffffffff82000200;
    
    anything_saved = (int (*)(void))(sys_call_table[__NR_syscall]);
    
    orig_cr0 = clear_and_return_cr0();
    // TODO: modify sys_call_table item
    sys_call_table[__NR_syscall] = (unsigned long)&sys_mycall; // 保持原赋值方式
    setback_cr0(orig_cr0);
    
    return 0;
}

/* 完全保留原退出函数 */
static void __exit exit_addsyscall(void)
{
    orig_cr0 = clear_and_return_cr0();
    sys_call_table[__NR_syscall] = (unsigned long)anything_saved;
    setback_cr0(orig_cr0);
}

module_init(init_addsyscall);
module_exit(exit_addsyscall);
MODULE_LICENSE("GPL");