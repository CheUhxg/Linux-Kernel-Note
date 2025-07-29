# AddMyEXT4

* 应用补丁，添加一个myext4文件系统。

## 实验步骤

* 执行以下步骤：

```bash
#!/bin/bash
# 1. 创建虚拟磁盘
dd if=/dev/zero of=myext4.img bs=1M count=100
# 2. 绑定到循环设备
sudo losetup /dev/loop0 myext4.img
# 3. 格式化
sudo mkfs.ext4 /dev/loop0
# 4. 挂载
sudo mount -t myext4 /dev/loop0 /mnt/myext4
```

* 成功后打印：

```bash
[ 7425.377781] MYEXT4-fs (loop0): mounted filesystem 06bf8063-dfec-4d76-af8c-57fc55444bfe r/w with ordered data mode.
[ 7425.380264] myext4 filesystem being mounted at /mnt/myext4 supports timestamps until 2038-01-19 (0x7fffffff)
```