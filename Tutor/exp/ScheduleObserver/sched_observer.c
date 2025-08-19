#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/sched/rt.h>  // 包含实时优先级定义
#include <uapi/linux/sched/types.h>

// 观察者线程数据结构
struct observer_thread {
    struct task_struct *task;
    atomic_t schedule_count;
    char name[16];
};

#define THREAD_NUM 2
static struct observer_thread threads[THREAD_NUM];

// 线程函数模板
static int observer_func(void *data) {
    struct observer_thread *info = (struct observer_thread *)data;

    while (!kthread_should_stop()) {
        // 统计调度次数（每次被唤醒执行时计数）
        atomic_inc(&info->schedule_count);
        
        // 让出 CPU
        schedule();
    }

    return 0;
}

// 模块初始化
static int __init sched_observer_init(void) {
    int i;

    printk(KERN_INFO "Initializing scheduler observer module...\n");

    // 初始化THREAD_NUM个线程
    for (i = 0; i < THREAD_NUM; i++) {
        atomic_set(&threads[i].schedule_count, 0);
        snprintf(threads[i].name, sizeof(threads[i].name), "observer_%d", i);
        
        // 创建线程并传递对应数据结构
        threads[i].task = kthread_run(observer_func, &threads[i], threads[i].name);
        if (IS_ERR(threads[i].task)) {
            printk(KERN_ERR "Failed to create thread %d\n", i);
            return PTR_ERR(threads[i].task);
        }

        // TODO: set thread priority
    }

    return 0;
}

// 模块退出
static void __exit sched_observer_exit(void) {
    int i;

    printk(KERN_INFO "Stopping threads...\n");

    // 停止所有线程并打印结果
    for (i = 0; i < THREAD_NUM; i++) {
        if (threads[i].task) {
            kthread_stop(threads[i].task);
            printk(KERN_INFO "Thread %d (%s) schedule count: %d\n",
                   i, threads[i].name, atomic_read(&threads[i].schedule_count));
        }
    }

    printk(KERN_INFO "Module unloaded.\n");
}

module_init(sched_observer_init);
module_exit(sched_observer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel Thread Schedule Counter");