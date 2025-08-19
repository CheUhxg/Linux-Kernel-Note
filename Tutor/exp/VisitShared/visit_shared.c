#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/mm.h>
#include <asm/ptrace.h>
#include <linux/atomic.h>

// /​**​​**​​**​​**​​**​​**​​**​​**​​**​ 共享变量与锁定义 ​**​​**​​**​​**​​**​​**​​**​​**​​**​/
static atomic_t shared_var = ATOMIC_INIT(0);

// 中断相关
static int irq_number = 12;          // 键盘中断IRQ1
static DEFINE_SPINLOCK(irq_lock);

// 异常相关
static DEFINE_SPINLOCK(exception_lock);
static void (*orig_page_fault)(struct pt_regs *, unsigned long, unsigned long);

// 工作队列相关
static DEFINE_MUTEX(work_mutex);
static struct delayed_work my_delayed_work;

// 确保使用共享标志和正确的dev_id
static struct my_dev_data {
    char name[16];
} dev_data = { .name = "my_mouse_irq" };

// /​**​​**​​**​​**​​**​​**​​**​​**​​**​​**​ 中断处理部分 ​**​​**​​**​​**​​**​​**​​**​​**​​**​​**​/
static irqreturn_t my_interrupt_handler(int irq, void *dev_id) {
    unsigned long flags;
    
    spin_lock_irqsave(&irq_lock, flags);
    atomic_add(5, &shared_var);
    spin_unlock_irqrestore(&irq_lock, flags);
    
    printk(KERN_INFO "Interrupt! Shared var: %d\n", atomic_read(&shared_var));
    return IRQ_HANDLED;
}

static int __init irq_init(void) {
    int ret = request_irq(irq_number, my_interrupt_handler, 
                         IRQF_SHARED, "my_irq", &dev_data);
    if (ret) 
        printk(KERN_ERR "Failed to register IRQ %d\n", irq_number);
    return ret;
}

static void __exit irq_cleanup(void) {
    free_irq(irq_number, NULL);
}

// /​**​​**​​**​​**​​**​​**​​**​​**​​**​ 可延迟函数部分 ​**​​**​​**​​**​​**​​**​​**​​**​​**​​**​/
static void deferred_work_handler(struct work_struct *work) {
    mutex_lock(&work_mutex);
    atomic_set(&shared_var, 100);
    mutex_unlock(&work_mutex);
    printk(KERN_INFO "Deferred work done! Shared var: %d\n", 
          atomic_read(&shared_var));
}

static int __init myworkqueue_init(void) {
    INIT_DELAYED_WORK(&my_delayed_work, deferred_work_handler);
    schedule_delayed_work(&my_delayed_work, HZ * 2);
    return 0;
}

static void __exit workqueue_cleanup(void) {
    cancel_delayed_work_sync(&my_delayed_work);
}

// /​**​​**​​**​​**​​**​​**​​**​​**​​**​ 模块主函数 ​**​​**​​**​​**​​**​​**​​**​​**​​**​​**​​**​/
static int __init main_init(void) {
    atomic_set(&shared_var, 0);
    
    if (irq_init() != 0) {
        printk(KERN_ERR "IRQ init failed\n");
        return -EIO;
    }
    
    // TODO: hook_page_fault();
    myworkqueue_init();
    
    printk(KERN_INFO "Module loaded. Shared var: %d\n", 
          atomic_read(&shared_var));
    return 0;
}

static void __exit main_exit(void) {
    irq_cleanup();
    // TODO: unhook_page_fault();
    workqueue_cleanup();
    printk(KERN_INFO "Module unloaded. Final value: %d\n", 
          atomic_read(&shared_var));
}

module_init(main_init);
module_exit(main_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");