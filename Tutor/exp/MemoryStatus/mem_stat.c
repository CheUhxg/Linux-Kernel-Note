#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/sysinfo.h>
#include <linux/sched/stat.h>
#include <linux/sched/loadavg.h>
#include <linux/time_namespace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YourName");
MODULE_DESCRIPTION("Kernel module to get memory usage info");

static int __init mem_stat_init(void)
{
	unsigned long mem_total, sav_total;
	unsigned int mem_unit, bitcount;
	struct timespec64 tp;
    struct sysinfo local_info;
    struct sysinfo *info = &local_info;

	memset(info, 0, sizeof(struct sysinfo));

	ktime_get_boottime_ts64(&tp);
	timens_add_boottime(&tp);
	info->uptime = tp.tv_sec + (tp.tv_nsec ? 1 : 0);

	si_meminfo(info);

	// TODO: print info correctly

    pr_info("System uptime: %lu s\n", info->uptime);
    pr_info("Total RAM: %lu kB\n", info->totalram / 1024);
    pr_info("Free RAM: %lu kB\n", info->freeram / 1024);
    pr_info("Shared RAM: %lu kB\n", info->sharedram / 1024);
    pr_info("Buffer RAM: %lu kB\n", info->bufferram / 1024);
    pr_info("Memory unit: %u\n", info->mem_unit);
out:
    return 0;
}

static void __exit mem_stat_exit(void)
{
    remove_proc_entry("mymem_stat", NULL);
    pr_info("Memory info module unloaded\n");
}

module_init(mem_stat_init);
module_exit(mem_stat_exit);
