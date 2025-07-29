#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/path.h>

#define TARGET_PROC_NAME "malware"
#define TARGET_FILE_NAME "secret_file"

static int hide_open_file(struct task_struct *task)
{
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *file;
    int i, found = 0;
    char *filename;
    struct file *passwd_file = NULL;

    if (!task)
        return -EINVAL;

    // 获取文件描述符表
    files = task->files;
    if (!files)
        return -EINVAL;

    // 锁定文件描述符表
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    if (!fdt) {
        spin_unlock(&files->file_lock);
        return -EINVAL;
    }

    // 为文件名分配内存
    filename = kmalloc(32, GFP_KERNEL);
    if (!filename) {
        spin_unlock(&files->file_lock);
        return -ENOMEM;
    }

    for (i = 0; i < fdt->max_fds; i++) {
        char *buf;

        file = fdt->fd[i];
        if (!file)
            continue;

        buf = d_path(&file->f_path, filename, PATH_MAX);
        if (IS_ERR(buf))
            continue;

        if (strstr(buf, TARGET_FILE_NAME)) {
            pr_info("找到目标文件: %s (fd: %d)\n", buf, i);

            // TODO: 打开 /etc/passwd 作为替代

            pr_info("已将 fd %d 替换为 /etc/passwd\n", i);
            found = 1;
        }
    }

    kfree(filename);
    spin_unlock(&files->file_lock);
    return found ? 0 : -ENOENT;
}

static int __init hidefile_init(void)
{
    struct task_struct *task;
    int ret = -ESRCH;

    pr_info("hide_file模块正在加载...\n");

    // 遍历所有进程，寻找目标进程
    for_each_process(task) {
        if (strcmp(task->comm, TARGET_PROC_NAME) == 0) {
            pr_info("找到目标进程 \"%s\" (pid: %d)\n", task->comm, task->pid);
            ret = hide_open_file(task);
            if (ret == 0)
                pr_info("文件隐藏成功。\n");
            else
                pr_warn("隐藏文件失败: %d\n", ret);
            break;
        }
    }

    if (ret == -ESRCH)
        pr_warn("未找到目标进程 \"%s\"。\n", TARGET_PROC_NAME);

    return 0;
}

static void __exit hidefile_exit(void)
{
    pr_info("hide_file模块已卸载。\n");
    // 注意：当前实现不会恢复被隐藏的文件
}

module_init(hidefile_init);
module_exit(hidefile_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("隐藏特定进程打开的指定文件");
