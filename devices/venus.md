# venus（小米 11）· HyperOS

范围只有一个：**小米 11（`venus` / M2011K2C）+ 澎湃 HyperOS**。不追求跨机型、跨内核通用。

## 镜像 = 内核 + ramdisk

`fastboot boot` 用的是镜像里的内核，不是手机里装的那个。所以：

- 同一台机器换了内核（原厂 qgki、Neko、别的第三方），**镜像也得跟着换**，否则
  `/vendor/lib/modules/*.ko` 的 vermagic 对不上，模块加载会 `Exec format error`；
  自定义内核改过的 config（SUSFS、uname 隐藏、binderfs 选项）也可能让 recovery 黑屏。
- `devices/venus.toml` 的 `[stock]` 指向 `stock-venus-boot.zip`，那是这台机器
  boot 分区的快照（TWRP ramdisk + Neko 内核）。**CI 产出的包就带这个内核**，
  纯原厂系统想用就得换内核，见下。

## 三种给别人用的方式（按稳妥排序）

1. **固化为常驻恢复（推荐）**
   `skyward embed <镜像>`，或界面里 高级 -> 固化为常驻恢复。
   它读的是**对方手机上 boot 分区此刻的内容**，只替换 ramdisk，内核和 boot 头原样保留，
   写前备份原分区。跟内核无关，也不用打包。

2. **`fastboot boot` 临时测试：用对方的 boot 当模板**
   ```sh
   adb shell su -c 'dd if=/dev/block/by-name/boot_a of=/sdcard/boot_a.img'
   skyward-pack boot --kernel boot_a.img --ramdisk skyward-venus-<sha>.img --out own-kernel.img
   ```
   `--kernel` 只取内核，头部（cmdline、OS_VERSION）仍来自 Skyward 的镜像。

3. **别做**：直接拿别人机器产出的镜像 `fastboot boot`。内核不同，风险自负。

## 另一处与内核无关的绑定

`devices/venus.toml` 里的 `[modules] load`、`[wlan] writes/firmware`、服务列表是按这台
机器的系统写的。换系统（比如 MIUI 14，见 `venus-miui14.md`）要另开分支改这些，内核不用改。