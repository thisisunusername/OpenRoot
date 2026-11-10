# OpenRoot

[English](README.md) | **简体中文**

![](https://i.imgs.ovh/2026/10/25/292fd26f3d676ca825fd439e2da0f1b5.png)

OpenRoot 是一个 Android 应用，它通过**两种通道之一**连接设备自身的 ADB 守护进程：无线调试配对，或 **Shizuku**。连上之后它会展示设备的真实信息，并可以运行内置载荷，在受支持的内核上获取临时 root。

加入 Shizuku 通道的原因是无线调试并非处处可用——有些设备的 Android 版本早于 11，还有些厂商定制系统直接把配对服务裁掉了。如果 Shizuku 已安装并获得授权，OpenRoot 完全不需要配对码。

## 功能

- **两种通道，一条管线。** 每一条 shell 命令、每一次文件推送和载荷执行都走同一个 `AdbShell` 辅助层，因此各个漏洞引擎无法区分当前用的是哪种通道。

- **Shizuku 通道。** 当 Shizuku 服务在运行、且本应用已获授权时，命令由 Shizuku 启动的本地进程执行（`/system/bin/sh -c …`）。无需配对，也不保存任何 ADB 密钥。

- **无线调试配对。** 通过 mDNS 发现 `_adb-tls-pairing._tcp`，从通知里收集 6 位配对码，完成 ADB 配对握手（TLS 1.3 密钥材料导出、edwards25519 上的 SPAKE2、AES-128-GCM 对端信息交换）。

- **配对一次，之后直连。** 配对成功会被记住，于是配对按钮消失，应用用已保存的 RSA 密钥直接连接。若直连失败，配对按钮会重新出现，可以再次用配对码。

- **通过 ADB 读取设备信息。** 名称、SoC、Android 版本、内核版本和 SELinux 模式都向已连接的守护进程查询（`getprop`、`uname -r`、`getenforce`），而不是读应用自己的 build props。

- **内核支持状态。** 主界面会报告已连接的内核是否有配套的 profile。

- **临时 root，十二个引擎，横跨十个 CVE 编号。** 选择器为每个引擎列一行；选定某一行后，才会挑选适配当前设备的构建，因此没有任何一行绑定到单一机型。在 arm64 设备上，应用会挑选能跑的那个引擎：

  - **CVE-2026-43499**（futex PI UAF）：把载荷与匹配精确 `uname -r` 的 profile 推送到 `/data/local/tmp/openroot`，以 `shell` 用户执行。

  - **CVE-2026-64560**（非 leader 线程 `exec()` 时的 posix-cpu-timers UAF）：把被释放的 `k_itimer` 转成物理读写原语，在子进程上布置 `init_cred`，再把这个子进程交给与其他引擎相同的 `bootstrap`。详见 `docs/CVE-2026-64560.md`。这个漏洞有三份构建，各自单独成行，因为分别是移植到不同内核族的：

    - 内置的 `PctRunner` 构建，针对一加 Ace 6（6.6.118 GKI）；
    - **CVE-2026-64560（Shark）**，针对 6.18 系列；
    - **CVE-2026-64560（JokerLock）**，针对 Oppo/Realme/一加 GKI 上的 `6.6.118-android15-8`，固件 `gc4127a25dcf3` / `g9bc34d5b0c79`。这份构建不读 profile，而是运行时通过 KernelSnitch 解析地址，并且对它改动过的内核状态做了可逆处理，所以失败一次仍然能正常开机。

  - **CVE-2025-21479**（Adreno A7xx 固件中 `CP_SMMU_TABLE_UPDATE` 检查绕过）：把 GPU 页表改写转成物理读写原语，打补丁 `__do_sys_capset`，再以 uid 0 重新执行已布置好的 `bootstrap`。

    这个原语依赖命中一个仍被 GPU 页表映射的内核物理地址，因此载荷会遍历一张候选地址表，并在每次尝试之间重启自身。重启是丢弃驱动每进程状态的唯一办法，而进程活着时驱动不会归还那块内存——这就是遍历在 `MAX_ATTEMPTS`（8）个候选后停止、而不是耗尽整张表的原因。在那些原语始终无法命中的设备上，耗尽整张表曾让内存占用超过 1 GB，把系统拖入持续换页。如果某台设备确实需要搜索更远，可以用 `CHEESE_MAX_ATTEMPTS=<n>` 覆盖；载荷是重启而不是原地重跑，所以每次尝试都要重新完整读一遍约 43 MB 的内核。

  - **CVE-2026-43284**（page cache 写入原语）：加载一个小内核模块。它不需要按设备定制的 profile，只要求内核主/次版本号与某个内置模块镜像匹配；它在应用进程内运行，因为用的是应用自己安装的 IPsec transform。

  - **CVE-2026-98260（Shark）** 和 **CVE-2026-61269（Shark）**：随同一批包进来的另外两份移植。`98260` 覆盖 6.18 系列，`61269` 覆盖 6.12 系列。两者都由各自随附的 shell 脚本驱动——脚本布置 `syms.txt`、推导 KASLR 偏移、运行攻击二进制并晚加载 `ksud`；应用只负责把文件拷过去并转发日志。
  - **CVE-2020-0069（联发科 `mtk-su`）**：这里是唯一一个**不是内核漏洞利用**的引擎。它以普通应用 uid 去驱动联发科命令队列节点，直接拿到 `uid=0`，此时 SELinux 已经是 permissive；随后由 `magiskinit` 在 `/sbin` 里拉起一份 Magisk 20.4 载荷。它不写任何分区、不涉及解锁 bootloader，代价是**重启后不保留**——这正是它能在完全解不开锁的设备上工作的原因。

    跑之前应用会先核对三件事：SoC 必须报告为联发科；命令队列节点（`/dev/mtk_cmdq` 及其同族）必须**能被 shell 用户打开**，而不只是存在；再拿构建的安全补丁级别与 2020 年 3 月的修复作比较。补丁更晚**不会**禁用这一行——真正能回答这个问题的只有载荷本身——但这一行会明说「大概率会失败」，而不是假装没事。32/64 位取自 `ro.product.cpu.abilist`，因为 `mtk-su32` 和 `mtk-su64` 是两个不同的二进制，选错只会得到 `exec format error`。

    由于这个引擎部署的是 Magisk 而不是 KernelSU，它配的是下文所述的老版管理器。它的载荷逐字节取自 `JunioJsv/mtk-easy-su`（`mtk-su32/64`、`magiskinit32/64`、`magisk-boot.sh`），见 `THIRD_PARTY_NOTICES.md`。
  - **CVE-2024-31317（zygote 参数注入）——前置，不是 root。** 这一行出现在选择器里，是因为它是唯一一个会改变「后续引擎能做什么」的引擎，标题里就写明了这一点。它把伪造的 zygote 参数（`--setuid=`、`--seinfo=`、`--invoke-with`）写进 `Settings.Global.hidden_api_blacklist_exemptions`，再启动一个应用，让 zygote 带着这些参数 fork。产出是以 `system`（`u:r:system_app:s0`）身份运行的代码——**仅 System 权限，永远不是 root**——这一行从不上报「已 root」，因为它从来就不是。

    有两件事让它敢被内置：它只在**安全补丁早于 2024 年 6 月**的 Android 12-13 上有效，窗口之外这一行会直接置灰，而不是写完才失败；那个危险的设置项会在 `finally` 里**无条件还原**，因为一旦把畸形值留在那个键里，设备就起不来了。上游参考实现是 200 ms 后重置然后听天由命；这里会等载荷自己写下的标记，无论成败都还原。被门禁的引擎读的是那个标记，而不是「没抛异常」。

    上游：<https://github.com/wqry085/PoC-Deployer-System>
  - **CVE-2026-49881 + CVE-2026-43284（LSPromise）**：合成一行，因为拆开后两半都做不成事。49881 是 Android 17 的 Telecom 逻辑漏洞，不需要任何额外权限就能在 `system_server` 里跑 Java；43284 就是上面那个 page cache 写入，但 SELinux 只把 `netlink_xfrm_socket` 授予 `system_server`、`network_stack` 和 `netd` 三个域。所以顺序只能是：49881 进 `system_server`，注入到 `com.android.networkstack`，DirtyFrag 的写入从那里发起。上面那一行**独立的 CVE-2026-43284 保持原样**——它是给「用别的方式够到 xfrm 的内核」准备的 page cache 引擎，不是这个引擎的旧版本。

    它要求 Android 17、已安装 KernelSU（最后一步会借用它的 `libksud.so`），以及 vermagic 与内置模块（`6.6.127-4k-g46a034eca005-dirty`）匹配的内核。6.1 系列在上游明确不受支持，而这**种不匹配是静默的**：`init_module` 在模块里任何代码跑起来之前就拒绝了它，所以这一行会拿运行中的 `uname -r` 去比模块自己的 vermagic 并直接说明，而不是加载完再祈祷。

    有一个必须讲清的边界：公开的这条链需要只存在于**应用进程内部**的 Java 对象（注册过的 `PhoneAccount`、让 `Shellcode` 被加载的 `AppComponentFactory`、把 networkstack binder 回传给应用用的 `BroadcastReceiver`）。本应用会把三个载荷推上设备并拉起 `shelld`，然后如实报告「`system_server` 这一半无法通过 ADB 驱动」——因为以 shell 用户启动的 `shelld` 继承的是 `shell` 标签，而该标签打不开 xfrm 套接字。这是**模型的边界，说明清楚**，不是把失败包装成别的说法。

    上游：<https://github.com/LSPosed/LSPromise>

  Shark 和 JokerLock 这两行来自第三方一键工具，因此被限制在那些工具所针对的内核族上。如果某个载荷自身的指纹校验不通过，它会打印 `TARGET_PROFILE_GATE_FAIL` 并停下，完全不碰内核——在任何其他构建上这都是预期结果，不是这一行的 bug。

  所有情况下，`ksud` 都会交给载荷（或为它布置好），使 KernelSU 在拿到 root 后立刻起来；当交接报告成功时，应用会自动打开管理器。

  当这一步失败时，流程不会直接掉到 shell。`native-or/bootstrap.c` 会沿一条梯子往下走，并报告自己走到了哪一级：

  ```
  ksud late-load  →  经 magiskinit 加载 Magisk  →  root 命令通道
  ```

  中间那一级正是「没有匹配的 `openroot-android*-*.ko`」变得不那么致命的原因：内核漏洞已经产出了 uid 0，于是这份 root 被用来拉起 Magisk，而不是浪费在一个光秃秃的 shell 上。成功与否看 `/sbin/su` 是否存在，而不看 `magiskinit` 的退出码——后者跨版本并不可靠。`dfmg1` 标记 Magisk 这一级，`dfm6` 是 KernelSU，`dfm7` 是命令通道；单独一个 `dfme2` 仍然表示什么都没加载成功，所以 Magisk 的标记要先读。

### 两个 Magisk 管理器，按载荷配对而非一并安装

  Magisk 是在两个相隔很远的年代被部署的，因此随包带两个管理器，由应用按载荷挑选：

  | 管理器 | 配对的载荷 | 原因 |
  | --- | --- | --- |
  | `manager-v8.0.4` | 联发科路径放在 `/sbin` 的 Magisk 20.4 | 新版管理器会拒绝这么老的 Magisk 并提示升级；而在锁定的 bootloader 上升级，是唯一能把设备变砖的办法 |
  | `v31.1` | 内核引擎部署的现代 Magisk 或 KernelSU | 它必须与自己所对话的守护进程版本匹配 |

  两个发行版的包名都是 `com.topjohnwu.magisk`，所以一台设备同一时间**只能装其中一个**，装另一个会覆盖前者。这就是为什么两者都不在构建期安装、也不会被静默预装：版本由实际加载的载荷决定，并且只在本次运行报告成功时才安装。要把新版换成老版还需先卸载，因为跨这么大的版本差 `pm install -r` 会拒绝降级。联发科载荷会打印与上游一致的警告：

  > 不要通过 Magisk 管理器更新 Magisk，否则在锁定的 bootloader 上会把设备变砖

## 环境要求

| 项目 | 要求 |
| --- | --- |
| Shizuku 通道 | 已安装并运行 Shizuku（root 或 ADB 方式），且已向 OpenRoot 授权 |
| 配对通道 | Android 11（API 30）或更新，且开启无线调试 |
| 载荷 | `arm64-v8a` 设备 |
| 构建 | JDK 17+、带 API 36 的 Android SDK；仅在重新编译载荷时需要 NDK r27d |

界面本身可在 Android 7.0（API 24）及以上运行。Shizuku 通道能在任何 Shizuku 本身可用的版本上工作，这正是它存在的意义；无线调试配对和载荷则需要更新的版本。

如果 Shizuku 是以 **root** 身份授权的，命令会以 uid 0 运行。如果是以 **ADB** 方式授权（uid 2000）——这是常见情况——载荷仍以 `shell` 身份运行，这与 ADB 连接能给你的权限完全一致。

## 构建

1. 让 Gradle 找到 SDK（`local.properties` 中的 `sdk.dir`）。
2. 构建：

```sh
./gradlew :app:assembleDebug
```

原生载荷以**预编译**形式提交在 `app/src/main/jniLibs/arm64-v8a/`，所以普通构建不需要 NDK。它们是从已发布的 release APK 中提取、原样打包的；下面的任务只在你显式要求时才会运行。

若要从源码重新编译载荷，设置 `OPENROOT_BUILD_NATIVE=1` 并安装 NDK r27d。构建会按此顺序查找：
`local.properties` 中的 `ndk.dir` → `ANDROID_NDK_HOME` → `NDK_ROOT` → `D:/android-ndk-r27d`。

```sh
OPENROOT_BUILD_NATIVE=1 ./gradlew :app:assembleDebug
```

设置该标志后，载荷由以下任务产出（否则各自跳过）：

- `buildNativeExploit` 在 `native/` 上运行 NDK 的 `make`，产出 `build/native/ghostlock`。
- `buildNativePageCache` 在 `build/or` 中产出 `libopenroot.so` 与 `libopenbootstrap.so`。
- `buildNativeGpu` 在 `build/gpu` 中产出 `libcheese-quest.so` 与 `libcheese-snapdragon.so`。
- `buildNativePct` 在 `build/pct` 中产出 `libpct-opace6.so`。
- `prepareNativePayloads` 是唯一会写入 `app/src/main/jniLibs/` 的任务。
- `stripNativePayloads` 对打包后的副本执行 strip。

手动编译载荷：

```sh
export NDK_ROOT=/path/to/android-ndk-r27d
make -C native ghostlock        # 产出 build/native/ghostlock
make -C native-or payload       # 产出 build/or/libopenroot.so, libopenbootstrap.so
make -C native-gpu payload      # 产出 build/gpu/libcheese-*.so
make -C native-pct payload      # 产出 build/pct/libpct-opace6.so
```

## 使用

### 使用 Shizuku

1. 安装 [Shizuku](https://shizuku.rikka.app/) 并启动它（root 方式，或从电脑用 ADB 启动）。
2. 打开 OpenRoot。如果服务在运行，主按钮会显示**授予 Shizuku 权限**；点它，并在 Shizuku 弹窗中允许请求。
3. 应用会立即连接。无需配对，也没有配对码要输入。

已授权不等于一定可用。OpenRoot 在信任这条链路之前，会先通过 `Shizuku.newProcess` 执行一个单词的 `echo`：如果某个 Shizuku 服务分支报告已授权却起不了进程（有些第三方实现就是这样），应用会显示**Shizuku 无法执行命令**，并回退到下面的 ADB 方式，而不是去申请一个其实已经有的权限。这条提示说明问题在服务端而不在权限——通常重启一次 Shizuku 服务就够了。

### 使用无线调试

1. 在设备的开发者选项中开启**无线调试**。
2. 打开 OpenRoot 并点**开始配对**。应用在寻找配对服务期间会保留一条前台通知。
3. 在设备上打开**使用配对码配对设备**，然后在通知里输入 6 位配对码。成功后配对按钮会隐藏。
4. 此后应用会自动连接。

### 使用普通 `adb tcpip` 端口

有些设备根本没有**无线调试**入口：设置被厂商裁掉了，或者系统版本早于 Android 11。这类设备通常仍跑着一个监听 TCP 的 `adbd`，由 `adb tcpip 5555` 或 `service.adb.tcp.port` 启动。OpenRoot 可以直接连接那个守护进程。

1. 在主按钮下方的输入框里填写地址。`127.0.0.1:5555` 指向本机上的守护进程；只填端口表示同一主机；也接受 `adb://host:port` 形式。
2. 点**连接**。

那个守护进程不会弹出*允许 USB 调试*提示，因此它会拒绝所有事先不知道的密钥，而允许列表位于 `/data/misc/adb/adb_keys`，`shell` 用户无法写入。解决办法是出示一个 `adbd` 已经接受的密钥：

3. 点**ADB 密钥**，粘贴一个已经成功连过本设备的 PKCS#8 私钥——例如来自某个曾在此设备上执行过 `adb connect` 的 Termux 安装目录中的 `~/.android/adbkey`——然后点**使用此密钥**。只需要 `-----BEGIN PRIVATE KEY-----` 那段，尾部的 `user@host` 行不需要。
4. 再次点**连接**。密钥会被保存，之后启动会复用它，输入框只在最近一次连接失败时才出现。

密钥不会被记录到日志，也不会离开应用的私有存储。密钥就位后，按钮上方的标签会显示**正在使用导入的 ADB 密钥**。

### 运行漏洞利用

连接成功后，**提权**按钮会出现在日志区域上方（在通道建立前一直隐藏）。点它打开引擎选择器。它会列出十二行（其中 31317 是前置、不是 root）；某一行若不可用会说明原因（此内核没有 profile、没有移植版本、GPU 不受支持、没有模块镜像覆盖此内核、此 ABI 未打包载荷、不是联发科设备、命令队列节点不可打开）。选定某一行后，才会挑选适配当前设备的载荷。原生日志显示在屏幕底部。

状态卡片会为已连接的设备显示 `支持`、`未验证` 或 `不支持`。

## 工作原理

```
MainActivity ──┬─ AdbPairingService ── mDNS ── PairingConnectionCtx ── PairingAuthCtx ── Spake2
               │                                                └── TLS 1.3 (bundled Conscrypt)
               ├─ AdbConnectionManager ──┬─ Transport.ADB     ── AdbConnection ─┐
               │                         └─ Transport.SHIZUKU ── ShizukuShell ──┤
               │                                                                └─ ShellStream
               ├─ AdbShell ── getprop / uname / getenforce / push / exec
               ├─ RootExploit    ── payload + profile ── /data/local/tmp/openroot
               ├─ DirtyFragRunner ── module + bootstrap ── /data/local/tmp/openroot
               ├─ GpuRunner      ── cheese + bootstrap ── /data/local/tmp/openroot
               └─ PctRunner      ── pct payload + bootstrap ── /data/local/tmp/openroot
```

- **`ShellStream` 是两种通道之间的接缝。** 它是一个五方法接口（`read`、`write`、`flush`、`isClosed`、`close`），有两份实现：`AdbStreamAdapter` 包装 ADB TLS 连接上的 `AdbStream`；`ShizukuStream` 包装 `ShizukuRemoteProcess`，并把它的 stdout 与 stderr 合并进同一个队列，因为 ADB 的 `shell:` 服务本来就把两者交错输出，载荷管线必须分辨不出差别。

- **`AdbConnectionManager` 负责挑选通道。** 它先试 Shizuku（无需密钥材料，无需 mDNS 往返），失败再回落到已配对的无线调试连接。`AbsAdbConnectionManager` 持有一个 `ShellProvider` 委托，因此 `manager.openStream("shell:…")` 对两者都原样可用。

- 配对用的 TLS 使用 APK 内置的 Conscrypt 副本，因此 `exportKeyingMaterial` 是一次普通的库调用，而不是对平台 provider 的隐藏 API 反射。

- SPAKE2 用纯 Java 实现（`crypto/spake2`），建立在一个自包含的小型 edwards25519 群（`Ed25519Group`）之上。掩码点就是标准的 SPAKE2 的 `M` 与 `N`。

- `adb/AdbShell.kt` 里的 shell 辅助函数在任意当前通道上流式执行命令；同一条通道也用来推送载荷及其 profile。

一处行为差异：Shizuku 进程是普通管道而非 tty，因此输出以 4 KiB 块到达，而不是逐行到达。`AdbShell` 本来就用显式的退出标记来框定命令，所以上层完全无感。

## 支持的内核与添加新设备

### 状态卡片的含义

| 状态 | 含义 |
| --- | --- |
| `支持` | 有 profile 精确匹配当前 `uname -r`，或此前另一个引擎在此构建上成功过 |
| `未验证` | 可以尝试某个引擎，但从未在此成功；设备是否真的存在漏洞，只有跑过才知道 |
| `不支持` | 没有匹配的 profile、没有模块镜像覆盖此内核主/次版本、此设备没有移植版本、GPU 不受支持，或设备不是 arm64 |

CVE-2026-43499 是精确的 profile 匹配，因此那里的 `支持` 意味着「此构建已被验证」。CVE-2026-43284、CVE-2025-21479 和 CVE-2026-64560 在不运行的情况下无法区分已修补与存在漏洞的内核或固件，所以它们从 `未验证` 起步，并记住首次运行的结果（按引擎、按 `uname -r` 记录）。

当 `ro.soc.*` / `ro.hardware.egl` / KGSL 的 `gpu_model` 节点识别出高通 Adreno GPU 时，会提供 CVE-2025-21479；随后用同一批 props 判断是头显还是手机构建。这只能证明 GPU 家族，不能证明固件版本，因此匹配的设备总是从 `未验证` 起步；一次成功的运行会把它变为 `支持`。

当 `ro.product.device` / `ro.build.fingerprint` 识别出有移植构建的设备时，会提供 CVE-2026-64560。载荷自带一道门：`--preflight` 比对完整指纹，其他一律拒绝，而被拒绝的运行不会被记录（它对漏洞是否存在什么都说明不了）。竞态是概率性的，因此一次运行预期要试若干次——每次最多 32 次——并且可能导致内核 panic，应用会把它作为普通失败上报。

载荷需要与目标内核**完全**匹配的 profile，包括 `-4k` 或 `-abogki...` 这类后缀。Profile 按完整 `uname -r` 字符串匹配，存放在 `app/src/main/assets/kernel_profiles/<release>.bin`。当该字符串没有对应文件时，应用报告 `不支持`。

添加一台设备：

1. 让 OpenRoot 连上该设备，读取主界面上的**内核**一行（或执行 `adb shell uname -r`）。原样复制该字符串。
2. 为该内核构建产出一个 profile。profile 是载荷读取的 GLK1 二进制布局：内核版本字符串、漏洞所需的结构体偏移，以及路由选择。偏移由该构建对应的设备自身 `boot.img`（或完整 OTA 包）推导。
3. 把文件保存为 `app/src/main/assets/kernel_profiles/<release>.bin`，例如
   `app/src/main/assets/kernel_profiles/6.1.138-android14-11-g0c3d559bcd85-ab14529422.bin`。
4. 重新构建并安装。状态卡片会切换为 `支持`；设备一连上，**提权**即可用。
5. 跑一次并观察日志。偏移错误的 profile 通常很早就以读取或查找错误失败，而不是拿到 root；在新 profile 成功跑通之前，请一律当作未验证。

注意事项：

- 不要重命名或裁剪版本字符串；`6.1.90-perf+` 和 `6.1.90-perf` 是两个不同的键。
- 多个 profile 可能共享同一个内核主版本但偏移不同。请按精确构建逐个添加文件，不要猜。
- 列出已内置的 profile：

```sh
ls app/src/main/assets/kernel_profiles
```

### 为 CVE-2026-64560 添加构建

该载荷不是 profile 驱动的：`init_task`、`init_cred`、`selinux_state` 以及 `misc` 链表的地址都是针对某一份构建硬编码的，直接映射与内核镜像之间的物理偏移量则是该 SoC 的常量。因此新构建需要自己的移植（上游提供 `tools/port_target.py`，可从解码后的 `Image` 重新生成源码）、`native-pct/` 下的新子目录、`native-pct/Makefile` 中的一个目标，以及 `PctRunner.Payload` 里的一条记录和紧挨着的指纹常量。载荷自身的 `--preflight` 就是那道门，因此半成品移植会在这里失败，而不是往错误的内核地址上写。

## 项目结构

```
app/src/main/java/com/hexo141/liquidglass/
  adb/        mDNS 发现、配对服务、ADB 连接、shell 辅助、SPAKE2 胶水
  crypto/     SPAKE2 上下文、edwards25519 群、标量归约
  device/     通过 ADB 读取的设备信息
  root/       载荷推送与执行
                MtkEasySu.kt     联发科免解锁路径：探测、布置、运行
                Zygote31317.kt   CVE-2024-31317 前置：窗口探测、注入、还原
                LSPromise.kt     CVE-2026-49881 + CVE-2026-43284：vermagic 门禁、布置、运行
                MagiskManager.kt 两个 Magisk 管理器及其配对关系
  ui/         液态玻璃组件与界面
native/       CVE-2026-43499 的 arm64 载荷源码（Makefile）
native-or/    CVE-2026-43284 的 arm64 载荷源码（Makefile）
native-gpu/   CVE-2025-21479 的 arm64 载荷源码（Makefile）
  quest/      zhuowei/cheese 构建（Quest 3/3S，XR2 Gen 2）
  snapdragon/ iqooneo8 移植（骁龙 8 Gen 1 / 8+ Gen 1）
native-pct/   CVE-2026-64560 的 arm64 载荷源码（Makefile）
  opace6/     一加 Ace 6 移植（CVE-2026-64560，6.6.118 GKI）
docs/         漏洞分析文档（CVE-2026-64560）
app/src/main/assets/kernel_profiles/   内置内核 profile
app/src/main/assets/mtk/               联发科载荷，取自 mtk-easy-su
app/src/main/assets/lspromise/         LSPromise 载荷，取自 LSPosed/LSPromise
```

## 相关链接

- CVE-2026-43499 上游：<https://github.com/YuKongA/ghostlock-app>
- CVE-2026-43284 上游：<https://github.com/diabl0w/DFRoot>
- CVE-2025-21479 上游（头显构建）：<https://github.com/zhuowei/cheese>
- CVE-2025-21479 上游（手机构建）：<https://github.com/Qingizi7/cve-2025-21479_iqooneo8>
- CVE-2026-64560 上游：<https://github.com/Wangs-official/opace6-cve-2026-64560>
- CVE-2026-64560 分析：[`docs/CVE-2026-64560.md`](docs/CVE-2026-64560.md)
- CVE-2020-0069 上游：<https://github.com/JunioJsv/mtk-easy-su>
- CVE-2020-0069（`mtk-su`）：<https://forum.xda-developers.com/t/amazing-temp-root-for-mediatek-armv8-2020-08-24.3922213/>
- CVE-2020-0069 背景：<https://www.xda-developers.com/mediatek-su-rootkit-exploit/>
- CVE-2024-31317 上游：<https://github.com/wqry085/PoC-Deployer-System>
- CVE-2026-49881 + CVE-2026-43284（LSPromise）上游：<https://github.com/LSPosed/LSPromise>
- Magisk 上游：<https://github.com/topjohnwu/Magisk>

## 持续集成

`.github/workflows/android.yml` 在每次推送到 `main`、每个 pull request，以及手动触发时构建（Actions 页面的 **Run workflow**）。它安装 JDK 21，运行 `./gradlew :app:assembleDebug`——载荷以预编译形式提交，因此不需要 NDK，也不需要签名密钥——然后把 APK 作为构建产物上传（保留 30 天），并发布一个以北京时间日期加 `-shizuku` 为标签的 release。

## 与原版的差异

本仓库在 [`hexo141/Openroot`](https://github.com/hexo141/Openroot) 的基础上加入了 Shizuku 通道，以及联发科引擎和 Magisk 降级这两层。其余部分——内核 profile、液态玻璃界面——保持一致。

- 新增：`adb/ShellStream.kt`、`adb/AdbStreamAdapter.kt`、`adb/ShizukuStream.kt`、`adb/ShizukuShell.kt`。
- 修改：`adb/AbsAdbConnectionManager.java`（新增 `ShellProvider` 委托与 `ShellStream` 的 `openStream`）、`adb/AdbShell.kt`、`adb/AdbConnectionManager.kt`、`MainActivity.kt`、`ui/PairingScreen.kt`、`AndroidManifest.xml`、`gradle/libs.versions.toml`、`app/build.gradle.kts`、`.gitignore`、本工作流。
- Shizuku 依赖：`dev.rikka.shizuku:api:13.0.0` 与 `:provider:13.0.0`。`Shizuku#newProcess` 在 13.1.5 变成 `private`，并将在 API 14 移除，因此这里是有意锁版本的；一旦越过它，就得改用 `UserService`，那需要 AIDL 和一个绑定服务的生命周期，而当前的载荷运行器没有这套东西。

## 许可证

见 `LICENSE`。第三方声明收集在 `THIRD_PARTY_NOTICES.md`。
