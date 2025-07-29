#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/fs.h>

// 初始化模块
static int __init traverse_all_vma_init(void)
{
    struct task_struct *task;
    struct vm_area_struct *vma;
    struct vma_iterator vmi;

    // 遍历系统中所有进程
    for_each_process(task) {
        struct mm_struct *mm = task->mm;

        // 如果进程没有 mm（例如内核线程），则跳过
        if (!mm)
            continue;

        pr_info("Process %d (%s):\n", task->pid, task->comm);

        // 初始化 vma_iterator
        vma_iter_init(&vmi, mm, 0);

        // 获取 mm->mmap_lock 的读锁
        mmap_read_lock(mm);

        // TODO: 使用 vma_next() 遍历所有 VMA

        // 释放锁
        mmap_read_unlock(mm);
    }

    return 0;
}

// 卸载模块
static void __exit traverse_all_vma_exit(void)
{
    pr_info("Module unloaded: traverse all VMA.\n");
}

module_init(traverse_all_vma_init);
module_exit(traverse_all_vma_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YourName");
MODULE_DESCRIPTION("Traverse virtual address space of all processes using kernel module");
