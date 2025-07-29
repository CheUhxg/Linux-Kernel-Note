# MemoryStatus

* 添加一个内核模块，加载模块时打印内核的物理内存状态。

## 实验要求

* 了解内核函数si_meminfo，正确打印info的字段，呈现如下效果：

```bash
[   43.242433][ T7907] System uptime: 44 s
[   43.242689][ T7907] Total RAM: 3975232 kB
[   43.242953][ T7907] Free RAM: 3389840 kB
[   43.243212][ T7907] Shared RAM: 6560 kB
[   43.243443][ T7907] Buffer RAM: 9440 kB
[   43.243649][ T7907] Memory unit: 1
```