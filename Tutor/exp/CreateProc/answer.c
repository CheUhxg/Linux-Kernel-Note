#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#define DIR_NAME "create_proc_dir"
#define FILE_NAME "create_proc_file"

static struct proc_dir_entry *my_dir = NULL;
static struct proc_dir_entry *my_file = NULL;

// 读取文件内容时调用的函数
static ssize_t my_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    const char *msg = "Hello from /proc/create_proc_dir/create_proc_file!\n";
    size_t len = strlen(msg);
    
    if (*ppos >= len)
        return 0;
    
    if (count > len - *ppos)
        count = len - *ppos;
    
    if (copy_to_user(buf, msg + *ppos, count))
        return -EFAULT;
    
    *ppos += count;
    return count;
}

// 写入文件内容时调用的函数（可选）
static ssize_t my_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    printk(KERN_INFO "Received data from user: %zu bytes\n", count);
    return count;
}

// 定义文件操作函数表
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops my_fops = {
    .proc_read = my_read,
    .proc_write = my_write,
};
#else
static const struct file_operations my_fops = {
    .read = my_read,
    .write = my_write,
};
#endif

// 模块初始化
static int __init create_proc_init(void) {
    // 在 /proc 下创建目录
    my_dir = proc_mkdir(DIR_NAME, NULL);
    if (!my_dir) {
        pr_err("Failed to create /proc/%s\n", DIR_NAME);
        return -ENOMEM;
    }

    // 在目录中创建文件
    my_file = proc_create(FILE_NAME, 0666, my_dir, &my_fops);
    if (!my_file) {
        proc_remove(my_dir);
        pr_err("Failed to create /proc/%s/%s\n", DIR_NAME, FILE_NAME);
        return -ENOMEM;
    }

    pr_info("Created /proc/%s/%s\n", DIR_NAME, FILE_NAME);
    return 0;
}

// 模块退出
static void __exit create_proc_exit(void) {
    proc_remove(my_file);
    proc_remove(my_dir);
    pr_info("Removed /proc/%s/%s\n", DIR_NAME, FILE_NAME);
}

module_init(create_proc_init);
module_exit(create_proc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Create custom files in /proc");