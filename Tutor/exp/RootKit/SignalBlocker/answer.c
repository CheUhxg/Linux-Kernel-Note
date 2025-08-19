// signal_blocker.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/kprobes.h>
#include <linux/signal.h>
#include <linux/string.h>  // 添加string.h用于strcmp函数

#define TARGET_PROC_NAME "malware"   // 要保护的进程名称
#define BLOCKED_SIG SIGINT           // 你想阻止的信号

static struct kprobe kp;

// pre_handler：在调用 do_send_sig_info 前执行
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    int sig = regs->di;
    struct task_struct *target = (struct task_struct *)regs->dx;

    // 检查目标进程名称是否为"malware"而不是特定PID
    if (target && !strcmp(target->comm, TARGET_PROC_NAME) && sig == BLOCKED_SIG) {
        pr_info("signal_blocker: 拦截信号 %d 到进程 '%s' (PID %d)\n", 
                sig, target->comm, target->pid);
        // 模拟信号发送成功，但实际上不传递
        regs->ax = 0;  // 设置返回值为 0（成功）
        return 1;      // 跳过原始函数调用
    }

    return 0;
}

static int __init signal_blocker_init(void)
{
    pr_info("signal_blocker: 正在加载模块\n");

    kp.symbol_name = "do_send_sig_info";
    kp.pre_handler = handler_pre;

    if (register_kprobe(&kp) < 0) {
        pr_err("signal_blocker: kprobe注册失败\n");
        return -1;
    }

    pr_info("signal_blocker: kprobe已注册到 %s\n", kp.symbol_name);
    return 0;
}

static void __exit signal_blocker_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("signal_blocker: 模块已卸载\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("基于Kprobe的信号拦截器，保护特定名称的进程");

module_init(signal_blocker_init);
module_exit(signal_blocker_exit);
