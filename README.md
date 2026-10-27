# OpenRoot
![](https://i.imgs.ovh/2026/10/25/292fd26f3d676ca825fd439e2da0f1b5.png)
OpenRoot is an Android app that reaches the device's own ADB daemon through **one of two
transports**: wireless debugging pairing, or **Shizuku**. It connects, shows what the device
actually is, and can run a bundled payload that grants temporary root on supported kernels.

The Shizuku transport exists because wireless debugging is not available everywhere — some devices
ship an Android release older than 11, and some vendor builds strip the pairing service entirely. If
Shizuku is installed and authorised, OpenRoot never needs a pairing code at all.

## Features

- **Two transports, one pipeline.** Every shell command, file push and payload run goes through the
  same `AdbShell` helper, so the exploit engines cannot tell which transport is in use.
- **Shizuku transport.** When the Shizuku service is running and this app has been granted access,
  commands run as a local process started by Shizuku (`/system/bin/sh -c …`). Nothing is paired and
  no ADB key is stored.
- **Wireless debugging pairing.** Discovers `_adb-tls-pairing._tcp` over mDNS, collects the six
  digit code from a notification, and completes the ADB pairing handshake (TLS 1.3 keying material
  export, SPAKE2 over edwards25519, AES-128-GCM peer info exchange).
- **Pair once, connect afterwards.** The successful pairing is remembered, so the pairing button
  disappears and the app connects directly with the stored RSA key. If the direct connection fails,
  the pairing button comes back and a code can be used again.
- **Device information over ADB.** Name, SoC, Android version, kernel release and SELinux mode are
  queried from the connected daemon (`getprop`, `uname -r`, `getenforce`), not from the app's own
  build props.
- **Kernel support status.** The main screen reports whether the connected kernel has a bundled
  profile.
- **Temporary root, four vulnerabilities.** The picker lists CVE ids, one row per bug; the build
  that fits the connected device is selected after the row is chosen, so no row is tied to a single
  device. On an arm64 device the app picks whichever engine can run:
  - **CVE-2026-43499** (futex PI UAF): the payload and a profile matching the exact `uname -r` are
    pushed to `/data/local/tmp/openroot` and executed as the `shell` user.
  - **CVE-2026-64560** (posix-cpu-timers UAF on non-leader `exec()`): the freed `k_itimer` is turned
    into a physical read/write primitive, `init_cred` is staged on a child, and that child is handed
    to the same `bootstrap` as the other engines. See `docs/CVE-2026-64560.md`.
  - **CVE-2025-21479** (`CP_SMMU_TABLE_UPDATE` check bypass in the Adreno A7xx firmware): the GPU
    page-table rewrite becomes a physical read/write primitive, `__do_sys_capset` is patched and the
    staged `bootstrap` is re-executed as uid 0.
  - **CVE-2026-43284** (page cache write primitive): loads a small kernel module. It needs no
    per-device profile, only a kernel major/minor that matches one of the bundled module images,
    and it runs inside the app process because it uses the IPsec transform the app installs.

  In every case `ksud` is handed to the payload (or staged for it) so KernelSU comes up right after
  root, and the manager is opened when the handoff reports success. If no manager is installed, the
  payloads that can keep one leave a root command channel instead.

## Requirements

| Item | Requirement |
| --- | --- |
| Shizuku transport | Shizuku app installed and running (root or ADB), access granted to OpenRoot |
| Pairing transport | Android 11 (API 30) or newer, wireless debugging enabled |
| Payload | `arm64-v8a` device |
| Build | JDK 17+, Android SDK with API 36; NDK r27d only when rebuilding the payloads |

The UI itself runs from Android 7.0 (API 24). The Shizuku transport works on any release where
Shizuku itself works, which is the whole reason it exists; wireless debugging pairing and the payload
need newer releases.

If Shizuku is granted as **root**, commands run as uid 0. If it is granted through **ADB**
(uid 2000) — the usual case — the payload still runs as `shell`, which is exactly what an ADB
connection would give you.

## Build

1. Point Gradle at the SDK (`local.properties`, `sdk.dir`).
2. Build:

```sh
./gradlew :app:assembleDebug
```

The native payloads are committed **prebuilt** in `app/src/main/jniLibs/arm64-v8a/`, so a plain
build needs no NDK. They are extracted from a published release APK and packaged as-is; the tasks
below only run when you ask for them.

To rebuild the payloads from source instead, set `OPENROOT_BUILD_NATIVE=1` and install NDK r27d.
The build looks for it in this order:
`ndk.dir` in `local.properties` → `ANDROID_NDK_HOME` → `NDK_ROOT` → `D:/android-ndk-r27d`.

```sh
OPENROOT_BUILD_NATIVE=1 ./gradlew :app:assembleDebug
```

With that flag set, the payloads are produced by these tasks (otherwise each is skipped):

- `buildNativeExploit` runs the NDK `make` over `native/` and produces `build/native/ghostlock`.
- `buildNativePageCache` produces `libopenroot.so` and `libopenbootstrap.so` in `build/or`.
- `buildNativeGpu` produces `libcheese-quest.so` and `libcheese-snapdragon.so` in `build/gpu`.
- `buildNativePct` produces `libpct-opace6.so` in `build/pct`.
- `prepareNativePayloads` is the only task that writes into `app/src/main/jniLibs/`.
- `stripNativePayloads` strips the packaged copies.

To build the payloads by hand:

```sh
export NDK_ROOT=/path/to/android-ndk-r27d
make -C native ghostlock        # writes build/native/ghostlock
make -C native-or payload       # writes build/or/libopenroot.so, libopenbootstrap.so
make -C native-gpu payload      # writes build/gpu/libcheese-*.so
make -C native-pct payload      # writes build/pct/libpct-opace6.so
```

## Usage

### With Shizuku

1. Install [Shizuku](https://shizuku.rikka.app/) and start it (root, or ADB from a computer).
2. Open OpenRoot. If the service is running, the primary button reads **Grant Shizuku access**;
   tap it and allow the request in the Shizuku dialog.
3. The app connects immediately. There is nothing to pair and no code to type.

### With wireless debugging

1. Enable **Wireless debugging** in Developer options on the device.
2. Open OpenRoot and tap **Start pairing**. The app keeps a foreground notification while it looks
   for the pairing service.
3. Open **Pair device with pairing code** on the device, then enter the six digit code in the
   notification. Once it succeeds, the pairing button is hidden.
4. From then on the app connects by itself.

### Running an exploit

Once connected, **Exploit** appears above the log area (it stays hidden until a transport is up).
Tap it to open the engine picker. It lists four CVE ids; a row explains why it cannot run (no profile
for this kernel, no ported build, GPU not supported, kernel not covered by the module images, payload
not packaged for this ABI). The payload that fits the connected device is chosen after the row is
picked. The native log is shown at the bottom of the screen.

The status card shows `Supported`, `Untested` or `Unsupported` for the connected device.

## How it works

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

- **`ShellStream` is the seam between the two transports.** It is a five-member interface
  (`read`, `write`, `flush`, `isClosed`, `close`) implemented twice: `AdbStreamAdapter` wraps an
  `AdbStream` on the ADB TLS connection, and `ShizukuStream` wraps a `ShizukuRemoteProcess` and
  merges its stdout and stderr into one queue, because an ADB `shell:` service already interleaves
  them and the payload pipeline must not be able to tell the difference.
- **`AdbConnectionManager` picks a transport.** It tries Shizuku first (no key material, no mDNS
  round trip) and falls back to the paired wireless debugging connection. `AbsAdbConnectionManager`
  holds a `ShellProvider` delegate, so `manager.openStream("shell:…")` works unchanged for both.
- Pairing TLS uses the Conscrypt copy bundled in the APK, so `exportKeyingMaterial` is a normal
  library call instead of a hidden-API reflection into the platform provider.
- SPAKE2 is implemented in plain Java (`crypto/spake2`) on top of a small self-contained
  edwards25519 group (`Ed25519Group`). The mask points are the standard SPAKE2 `M` and `N`.
- The shell helpers in `adb/AdbShell.kt` stream commands over whichever transport is live; the same
  channel is used to push the payload and its profile.

One behaviour difference: a Shizuku process is a plain pipe, not a tty, so output arrives in 4 KiB
blocks instead of line by line. `AdbShell` already frames commands with an explicit exit marker, so
nothing above it cares.

## Supported kernels and adding a new device

### What the status card means

| State | Meaning |
| --- | --- |
| `Supported` | A kernel profile matches this exact `uname -r`, or a previous run of another engine succeeded on this build |
| `Untested` | An engine can be attempted but has never succeeded here; whether the device is actually vulnerable is only known after a run |
| `Unsupported` | No profile matches, no module image covers this kernel major/minor, no ported build exists for this device, the GPU is not supported, or the device is not arm64 |

CVE-2026-43499 is an exact profile match, so `Supported` there means "this build was verified".
CVE-2026-43284, CVE-2025-21479 and CVE-2026-64560 cannot tell a patched kernel or firmware from a
vulnerable one without running, which is why they start as `Untested` and remember the outcome of
the first run (per engine, keyed by `uname -r`).

CVE-2025-21479 is offered when `ro.soc.*` / `ro.hardware.egl` / the KGSL `gpu_model` node identify a
Qualcomm Adreno GPU; the headset or phone build is then picked from the same props. That only proves
the GPU family, not the firmware revision, so a matching device always starts as `Untested`; a
successful run moves it to `Supported`.

CVE-2026-64560 is offered when `ro.product.device` / `ro.build.fingerprint` identify a device with a
ported build. The payload carries its own gate: `--preflight` compares the full fingerprint and
refuses anything else, and a refused run is not recorded (it says nothing about the vulnerability).
The race is probabilistic, so a run is expected to take several attempts — up to 32 per run — and
may panic the kernel, which the app reports as a normal failure.

The payload needs a profile that matches the target kernel **exactly**, including suffixes such as
`-4k` or `-abogki...`. Profiles are matched by the full `uname -r` string and live in
`app/src/main/assets/kernel_profiles/<release>.bin`. The app reports `Unsupported` when the string
has no matching file.

To add a device:

1. Connect OpenRoot to the device and read the **Kernel** line on the main screen (or run
   `adb shell uname -r`). Copy the string exactly.
2. Produce a profile for that kernel build. A profile is the GLK1 binary layout the payload reads:
   the kernel release, the structure offsets the exploit needs, and the route selection. Offsets are
   derived from the device's own `boot.img` (or a full OTA package) for that build.
3. Save the file as `app/src/main/assets/kernel_profiles/<release>.bin`, for example
   `app/src/main/assets/kernel_profiles/6.1.138-android14-11-g0c3d559bcd85-ab14529422.bin`.
4. Rebuild and install. The status card switches to `Supported`; **Exploit** is available as soon
   as the device is connected.
5. Run it once and watch the log. A profile with wrong offsets usually fails early with a read or
   lookup error instead of gaining root; treat a new profile as unverified until a run succeeds.

Notes:

- Do not rename or trim the release string; `6.1.90-perf+` and `6.1.90-perf` are different keys.
- Several profiles may share a kernel major version but differ in offsets. Add one file per exact
  build rather than guessing.
- To list what is bundled:

```sh
ls app/src/main/assets/kernel_profiles
```

### Adding a build for CVE-2026-64560

That payload is not profile-driven: the addresses of `init_task`, `init_cred`, `selinux_state` and
the `misc` list are baked in for one build, and the physical delta between the direct map and the
kernel image is a constant of that SoC. A new build therefore needs its own port (upstream ships
`tools/port_target.py`, which regenerates the source from a decoded `Image`), a new subdirectory
under `native-pct/`, a target in `native-pct/Makefile` and an entry in `PctRunner.Payload` plus the
fingerprint constants next to it. The payload's own `--preflight` is the gate, so a half-ported
build fails there instead of writing to the wrong kernel address.

## Project layout

```
app/src/main/java/com/hexo141/liquidglass/
  adb/        mDNS discovery, pairing service, ADB connection, shell helpers, SPAKE2 glue
  crypto/     SPAKE2 context, edwards25519 group, scalar reduction
  device/     device information read over ADB
  root/       payload push and execution
  ui/         liquid glass components and screens
native/       arm64 payload sources for CVE-2026-43499 (Makefile)
native-or/    arm64 payload sources for CVE-2026-43284 (Makefile)
native-gpu/   arm64 payload sources for CVE-2025-21479 (Makefile)
  quest/      zhuowei/cheese build (Quest 3/3S, XR2 Gen 2)
  snapdragon/ iqooneo8 port (Snapdragon 8 Gen 1 / 8+ Gen 1)
native-pct/   arm64 payload sources for CVE-2026-64560 (Makefile)
  opace6/     OnePlus Ace 6 port (CVE-2026-64560, 6.6.118 GKI)
docs/         vulnerability write-ups (CVE-2026-64560)
app/src/main/assets/kernel_profiles/   bundled kernel profiles
```

## Links

- CVE-2026-43499 upstream: <https://github.com/YuKongA/ghostlock-app>
- CVE-2026-43284 upstream: <https://github.com/diabl0w/DFRoot>
- CVE-2025-21479 upstream (headset build): <https://github.com/zhuowei/cheese>
- CVE-2025-21479 upstream (phone build): <https://github.com/Qingizi7/cve-2025-21479_iqooneo8>
- CVE-2026-64560 upstream: <https://github.com/Wangs-official/opace6-cve-2026-64560>
- CVE-2026-64560 write-up: [`docs/CVE-2026-64560.md`](docs/CVE-2026-64560.md)

## Continuous integration

`.github/workflows/android.yml` builds on every push to `main`, on pull requests, and on demand
(**Run workflow** in the Actions tab). It installs JDK 21, runs `./gradlew :app:assembleDebug` — the
payloads are committed prebuilt, so no NDK and no signing secrets are needed — then uploads the APK
as a build artifact (kept 30 days) and publishes a release tagged with the Beijing date plus
`-shizuku`.

## Differences from upstream

This tree adds the Shizuku transport on top of
[`hexo141/Openroot`](https://github.com/hexo141/Openroot). Everything else — the four CVE engines,
the kernel profiles, the liquid glass UI — is unchanged.

- New: `adb/ShellStream.kt`, `adb/AdbStreamAdapter.kt`, `adb/ShizukuStream.kt`, `adb/ShizukuShell.kt`.
- Changed: `adb/AbsAdbConnectionManager.java` (a `ShellProvider` delegate plus a `ShellStream`
  `openStream`), `adb/AdbShell.kt`, `adb/AdbConnectionManager.kt`, `MainActivity.kt`,
  `ui/PairingScreen.kt`, `AndroidManifest.xml`, `gradle/libs.versions.toml`,
  `app/build.gradle.kts`, `.gitignore`, this workflow.
- Shizuku dependency: `dev.rikka.shizuku:api:13.0.0` and `:provider:13.0.0`. `Shizuku#newProcess`
  became `private` in 13.1.5 and is slated for removal in API 14, so this is pinned deliberately;
  moving past it means switching to a `UserService`, which needs AIDL and a bound-service lifecycle
  the payload runners do not currently have.

## License

See `LICENSE`. Third-party notices are collected in `THIRD_PARTY_NOTICES.md`.
