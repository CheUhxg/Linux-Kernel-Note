# TraverseVMA

* 添加一个内核模块，遍历所有进程的VMA。

## 实验要求

* 完善TODO的遍历VMA过程，呈现如下效果：

```bash
[ 1105.841343]   VMA: 0x7f3cab901000 - 0x7f3cab902000, flags: 0x8100073, file: libresolv-2.31.so
[ 1105.842067]   VMA: 0x7f3cab902000 - 0x7f3cab904000, flags: 0x8100073, file: anonymous
[ 1105.842467]   VMA: 0x7f3cab904000 - 0x7f3cab906000, flags: 0x8000071, file: libkeyutils.so.1.8
[ 1105.842902]   VMA: 0x7f3cab906000 - 0x7f3cab908000, flags: 0x8000075, file: libkeyutils.so.1.8
[ 1105.843336]   VMA: 0x7f3cab908000 - 0x7f3cab909000, flags: 0x8000071, file: libkeyutils.so.1.8
[ 1105.843769]   VMA: 0x7f3cab909000 - 0x7f3cab90a000, flags: 0x8100071, file: libkeyutils.so.1.8
[ 1105.844205]   VMA: 0x7f3cab90a000 - 0x7f3cab90b000, flags: 0x8100073, file: libkeyutils.so.1.8
[ 1105.844643]   VMA: 0x7f3cab90b000 - 0x7f3cab90f000, flags: 0x8000071, file: libgpg-error.so.0.28.0
[ 1105.845095]   VMA: 0x7f3cab90f000 - 0x7f3cab922000, flags: 0x8000075, file: libgpg-error.so.0.28.0
[ 1105.845543]   VMA: 0x7f3cab922000 - 0x7f3cab92c000, flags: 0x8000071, file: libgpg-error.so.0.28.0
...
```