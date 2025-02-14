| 配置项 | 说明 |
| --- | --- |
| `CONFIG_BUG=y` | 启用内核中的BUG报告机制，确保能报告各种内核硬化操作。 |
| `CONFIG_STRICT_KERNEL_RWX=y` | 强制内核内存区域的可执行性、可读性和可写性进行严格的权限控制，从而减少攻击面。 |
| `CONFIG_STRICT_MODULE_RWX=y` | 强制内核模块（如驱动程序）的内存区域具有严格的权限控制，防止攻击者执行恶意代码。 |
| `CONFIG_VMAP_STACK=y` | 启用堆栈的虚拟内存映射，增加栈溢出攻击的难度。 |
| `CONFIG_RANDOMIZE_BASE=y` | 启用内核基础地址的随机化（ASLR）。这样可以使攻击者难以预测内核的位置。 |
| `CONFIG_RANDOMIZE_MEMORY=y` | 启用内核内存的随机化，增加内存布局的不确定性，进一步加强攻击难度。 |
| `CONFIG_SLAB_FREELIST_RANDOM=y` | 随机化slab分配器的freelist（自由链表），增加堆分配的不可预测性。 |
| `CONFIG_SLAB_FREELIST_HARDENED=y` | 对slab分配器的freelist进行硬化，以减少针对分配器的攻击面。 |
| `CONFIG_SLAB_BUCKETS=y` | 启用slab分配器的桶化机制，提高内存分配的安全性。 |
| `CONFIG_SHUFFLE_PAGE_ALLOCATOR=y` | 启用页面分配器的随机化，增强堆分配的随机性，增加攻击者的猜测难度。 |
| `CONFIG_RANDOM_KMALLOC_CACHES=y` | 随机化kmalloc缓存池的分配，减少内存分配的预测性。 |
| `CONFIG_PAGE_TABLE_CHECK=y` | 启用页表检查，增加对恶意内存写操作的检测。 |
| `CONFIG_PAGE_TABLE_CHECK_ENFORCED=y` | 强制执行页表检查，防止用户空间访问不允许的内存区域。 |
| `CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y` | 随机化内核栈的偏移量，增加栈溢出攻击的难度。 |
| `CONFIG_STACKPROTECTOR=y` | 启用栈保护（Stack Protector），通过在栈上添加保护值来防止栈溢出攻击。 |
| `CONFIG_STACKPROTECTOR_STRONG=y` | 启用更强的栈保护机制，增强对栈溢出攻击的防护能力。 |
| `CONFIG_HARDENED_USERCOPY=y` | 确保内核在执行内存拷贝时会对拷贝长度进行检查，防止越界访问。 |
| `CONFIG_FORTIFY_SOURCE=y` | 启用编译器的“FORTIFY”功能，通过内置的缓冲区检查防止常见的内存漏洞。 |
| `CONFIG_UBSAN=y` | 启用未定义行为检查（UBSAN），可以捕获例如数组越界、整数溢出等错误。 |
| `CONFIG_UBSAN_TRAP=y` | 启用触发未定义行为时的崩溃处理，方便开发者发现潜在错误。 |
| `CONFIG_UBSAN_BOUNDS=y` | 启用对数组下标越界等错误的检查，防止访问越界的内存。 |
| `CONFIG_KFENCE=y` | 启用基于采样的堆溢出和使用后释放（UAF）检测，增强内存安全性。 |
| `CONFIG_LIST_HARDENED=y` | 启用链表的完整性检查，防止链表操作中发生破坏性修改。 |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` | 默认启用堆分配时将内存初始化为零，以避免使用未初始化的内存。 |
| `CONFIG_INIT_STACK_ALL_ZERO=y` | 默认启用栈变量初始化为零，防止栈溢出攻击利用未初始化的栈数据。 |
| `CONFIG_RESET_ATTACK_MITIGATION=y` | 启用在系统重启时通过EFI清除RAM的功能，以防止冷启动攻击。 |
| `CONFIG_EFI_DISABLE_PCI_DMA=y` | 禁止EFI手off后到内核IOMMU设置之前的DMA操作，防止恶意设备通过DMA攻击内核。 |
| `CONFIG_IOMMU_SUPPORT=y` | 启用IOMMU（输入输出内存管理单元）支持，增强设备访问内存的安全性。 |
| `CONFIG_IOMMU_DEFAULT_DMA_STRICT=y` | 强制IOMMU进行严格的DMA访问控制，防止恶意设备访问内核内存。 |
| `CONFIG_STRICT_DEVMEM=y` | 禁止直接访问设备内存，防止非设备的内存被错误访问。 |
| `CONFIG_IO_STRICT_DEVMEM=y` | 强制设备内存访问进行更严格的检查，减少硬件和内核之间的潜在攻击面。 |
| `CONFIG_SECCOMP=y` | 启用seccomp（安全计算模式），减少系统调用接口的攻击面。 |
| `CONFIG_SECCOMP_FILTER=y` | 启用seccomp过滤器，通过BPF过滤系统调用，增加系统调用的安全性。 |
| `CONFIG_SYN_COOKIES=y` | 启用SYN Cookie防御机制，防止SYN洪水攻击。 |
| `CONFIG_CFI_CLANG=y` | 启用Clang的控制流完整性（CFI）支持，可以检测并阻止控制流篡改攻击。 |
| `CONFIG_LDISC_AUTOLOAD is not set` | 禁用自动加载TTY行控制子系统，减少TTY设备的攻击面。 |
| `CONFIG_COMPAT_BRK is not set` | 禁用兼容性brk系统调用，防止通过brk修改用户空间地址空间布局的攻击。 |
| `CONFIG_PROC_KCORE is not set` | 禁用暴露内核文本映像布局（kcore），减少攻击者对内核内部结构的了解。 |
| `CONFIG_COMPAT_VDSO is not set` | 禁用兼容性VDSO，防止暴露用户空间的VDSO布局。 |
| `CONFIG_LEGACY_PTYS is not set` | 禁用旧版PTY接口，仅使用现代PTY接口（devpts），减少攻击面。 |