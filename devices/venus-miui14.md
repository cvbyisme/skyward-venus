# venus 的 MIUI 14 版本

同一个机型（`venus` / M2011K2C / 骁龙 888）上跑着两种系统，Skyward 的代码是一样的，
不一样的是**用哪一份 boot 当模板**。

## 差别在哪

| | HyperOS OS3.0.315.0.WPBCNXM | MIUI 14 (Android 13) |
| --- | --- | --- |
| kernel sha256 | `e1988950a2f072115f3720f61bbe4b624d57476aa32f66f4bdf7c3996957e2c3` | `d87cd3903a77a1a93a41baf6eccd237d8db9c7b7b48faf501dc1a689eeb2fb8a` |
| 模板来源 | 随机附带 `boot_a.img` 解出的 ramdisk | 对方机器 `GeekFlashTool` Readback 的 `boot_a.img` |

两台机器的 kernel 大小一样（46,840,320 字节），内容却完全不同，所以**内核不能混用**：
拿 HyperOS 的 kernel 去 boot MIUI 14 的机器，结果就是黑屏，而且 `/persist/skyward.log`
一行都不会写（程序根本没机会跑）。

## 打一份 MIUI 14 用的镜像

```sh
magiskboot unpack <对方机器的 boot_a.img>          # 取它的 kernel 和 ramdisk
# 只换 boot 头里的 cmdline（fastboot boot 需要 twrpfastboot=1），其余原样继承
mkdir -p p && cd p
cp <对方 kernel> kernel
cp <skyward CI 产出的 ramdisk.cpio> ramdisk.cpio
magiskboot repack <改过 cmdline 的对方 boot.img> out.img
```

头部字段建议与模板一致（或照 d14 那样写 `15.0.0` / `2099-12`），
`OS_VERSION` 这一个 32 位字里的布局是：

```
A << 25 | B << 18 | C << 11 | (year - 2000) << 4 | month
```

## 刷法

```sh
fastboot boot out.img
```

**不要** `fastboot flash boot_a`——这只是一份恢复镜像，刷进 boot 分区会让手机开不了机。
想长期使用，进 Skyward 后在 TWRP 里用 *Install Recovery Ramdisk* 挂到系统上，
或者刷回原厂 boot。

## 已经验证过什么

- HyperOS 版本：可以读 `/sdcard`、可以刷 zip（Skyward 用户确认）。
- MIUI 14 版本：镜像头部与内核已校对（cmdline `twrpfastboot=1`、kernel 与机器自身一致），待上机。
