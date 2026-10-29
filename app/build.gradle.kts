import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Date-based version, same format and timezone as the release tag the CI publishes (v20261025).
// CI exports DATE, so the APK version always equals the tag; local builds use the Beijing date.
val buildDate: String = System.getenv("DATE")
    ?.takeIf { it.matches(Regex("""\d{8}""")) }
    ?: LocalDate.now(ZoneId.of("Asia/Shanghai")).format(DateTimeFormatter.BASIC_ISO_DATE)

android {
    namespace = "com.hexo141.liquidglass"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.hexo141.liquidglass"
        minSdk = 24
        targetSdk = 36
        // A date versionCode also lets a newer APK install over an older one.
        versionCode = buildDate.toInt()
        versionName = "v$buildDate"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    packaging {
        jniLibs {
            // conscrypt-android ships .so files that are not 16KB-page aligned; extracting them
            // at install time avoids load failures on 16KB page size devices
            useLegacyPackaging = true
        }
    }
}

// ---------------------------------------------------------------------------
// Native payloads
//
// The payloads are committed prebuilt in src/main/jniLibs/arm64-v8a, extracted from the
// published release APK:
//   native/      kernel-profile payload (libghostlock.so)
//   native-or/   page cache payload     (libopenroot.so + libopenbootstrap.so)
//   native-gpu/  Adreno GPU payloads    (libcheese-quest.so + libcheese-snapdragon.so)
//   native-pct/  posix-cpu-timers UAF   (libpct-opace6.so)
//
// Building them from source needs an x86_64 NDK, which Google does not publish for aarch64
// hosts, so the default build reuses the committed .so files. Set OPENROOT_BUILD_NATIVE=1 to
// compile them instead (ndk.dir in local.properties, or ANDROID_NDK_HOME / NDK_ROOT).
// ---------------------------------------------------------------------------

val buildNative: Boolean = System.getenv("OPENROOT_BUILD_NATIVE") == "1"

/** NDK location: local.properties -> ANDROID_NDK_HOME -> NDK_ROOT -> D:/android-ndk-r27d. */
fun resolveNdkDir(): String {
    val properties = Properties()
    val propertiesFile = rootProject.file("local.properties")
    if (propertiesFile.isFile) propertiesFile.inputStream().use(properties::load)
    return sequenceOf(
        properties.getProperty("ndk.dir"),
        System.getenv("ANDROID_NDK_HOME"),
        System.getenv("NDK_ROOT"),
        "D:/android-ndk-r27d",
    ).firstOrNull { !it.isNullOrBlank() } ?: ""
}

val ndkDir: String = if (buildNative) {
    resolveNdkDir().ifEmpty {
        error(
            "OPENROOT_BUILD_NATIVE=1 needs an NDK. Set ndk.dir in local.properties or " +
                "ANDROID_NDK_HOME. Unset OPENROOT_BUILD_NATIVE to use the committed payloads."
        )
    }
} else {
    ""
}
val ndkPrebuilt: String = when {
    System.getProperty("os.name").lowercase().contains("win") -> "windows-x86_64"
    System.getProperty("os.name").lowercase().contains("mac") -> "darwin-x86_64"
    else -> "linux-x86_64"
}
val ndkBinDir: String = "$ndkDir/toolchains/llvm/prebuilt/$ndkPrebuilt/bin"
val ndkMake: String = "$ndkDir/prebuilt/$ndkPrebuilt/bin/${if (ndkPrebuilt == "windows-x86_64") "make.exe" else "make"}"
val ndkStrip: String = "$ndkBinDir/${if (ndkPrebuilt == "windows-x86_64") "llvm-strip.exe" else "llvm-strip"}"

val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs/arm64-v8a")

val buildNativeExploit = tasks.register<Exec>("buildNativeExploit") {
    group = "build"
    description = "Compiles the arm64 kernel-profile payload with the NDK"
    enabled = buildNative
    workingDir = rootProject.layout.projectDirectory.dir("native").asFile
    commandLine(ndkMake, "ghostlock", "-j4")
    environment("NDK_ROOT", ndkDir)
    inputs.dir(rootProject.layout.projectDirectory.dir("native/core"))
    inputs.file(rootProject.layout.projectDirectory.file("native/Makefile"))
    outputs.file(layout.buildDirectory.file("native/ghostlock"))
}

val buildNativePageCache = tasks.register<Exec>("buildNativePageCache") {
    group = "build"
    description = "Compiles the arm64 page cache payload with the NDK"
    enabled = buildNative
    workingDir = rootProject.layout.projectDirectory.dir("native-or").asFile
    commandLine(ndkMake, "payload", "-j4")
    environment("NDK_ROOT", ndkDir)
    inputs.dir(rootProject.layout.projectDirectory.dir("native-or"))
    outputs.dir(layout.buildDirectory.dir("or"))
}

val buildNativeGpu = tasks.register<Exec>("buildNativeGpu") {
    group = "build"
    description = "Compiles the arm64 Adreno GPU payloads with the NDK"
    enabled = buildNative
    workingDir = rootProject.layout.projectDirectory.dir("native-gpu").asFile
    commandLine(ndkMake, "payload", "-j4")
    environment("NDK_ROOT", ndkDir)
    inputs.dir(rootProject.layout.projectDirectory.dir("native-gpu"))
    outputs.dir(layout.buildDirectory.dir("gpu"))
}

val buildNativePct = tasks.register<Exec>("buildNativePct") {
    group = "build"
    description = "Compiles the arm64 posix-cpu-timers payload with the NDK"
    enabled = buildNative
    workingDir = rootProject.layout.projectDirectory.dir("native-pct").asFile
    commandLine(ndkMake, "payload", "-j4")
    environment("NDK_ROOT", ndkDir)
    inputs.dir(rootProject.layout.projectDirectory.dir("native-pct"))
    outputs.dir(layout.buildDirectory.dir("pct"))
}

/**
 * CVE-2020-0041: the binder out-of-bounds write payload for 5.4 and 5.4-qgki.
 *
 * Built with `ndk-build` rather than a hand-written Makefile because that is what the upstream PoC
 * ships with; `Android.mk` names the module `binder54` and `Application.mk` pins arm64-v8a.
 */
val buildNativeBinder54 = tasks.register<Exec>("buildNativeBinder54") {
    group = "build"
    description = "Compiles the arm64 binder OOB-write payload with the NDK"
    enabled = buildNative
    workingDir = rootProject.layout.projectDirectory.dir("native-binder54").asFile
    val ndkBuild = "$ndkDir/ndk-build"
    commandLine(
        if (System.getProperty("os.name").lowercase().contains("win")) "$ndkBuild.cmd" else ndkBuild,
        "-j4",
        "NDK_PROJECT_PATH=.",
        "APP_BUILD_SCRIPT=Android.mk",
        "NDK_APPLICATION_MK=Application.mk",
        "NDK_OUT=build/obj",
        "NDK_LIBS_OUT=build/libs",
    )
    inputs.dir(rootProject.layout.projectDirectory.dir("native-binder54"))
    // ndk-build writes executables under `$NDK_LIBS_OUT/<abi>/`; the ABI comes from Application.mk.
    outputs.file(layout.buildDirectory.file("binder54/arm64-v8a/binder54"))
}

/**
 * The only task that writes into jniLibs. When the payloads are prebuilt this does nothing, so
 * the committed .so files are packaged exactly as they were released.
 */
val prepareNativePayloads = tasks.register<Copy>("prepareNativePayloads") {
    group = "build"
    description = "Copies every compiled payload into jniLibs"
    enabled = buildNative
    dependsOn(buildNativeExploit, buildNativePageCache, buildNativeGpu, buildNativePct)
    dependsOn(buildNativeBinder54)
    from(layout.buildDirectory.file("native/ghostlock")) {
        rename { "libghostlock.so" }
    }
    from(layout.buildDirectory.dir("or")) {
        include("libopenroot.so", "libopenbootstrap.so")
    }
    from(layout.buildDirectory.dir("gpu")) {
        include("libcheese-quest.so", "libcheese-snapdragon.so")
    }
    from(layout.buildDirectory.dir("pct")) {
        include("libpct-opace6.so")
    }
    // Android only unpacks `lib*.so` from jniLibs, so the executable is packaged under a library
    // name; nativeLibraryDir exposes it at that name and the runner execs it as a file.
    from(layout.buildDirectory.dir("binder54/arm64-v8a")) {
        include("binder54")
        rename { "libbinder54.so" }
    }
    into(jniLibsDir)
}

val stripNativePayloads = tasks.register<Exec>("stripNativePayloads") {
    group = "build"
    description = "Strips the packaged payloads"
    enabled = buildNative
    dependsOn(prepareNativePayloads)
    val targets = listOf(
        "libghostlock.so",
        "libopenroot.so",
        "libopenbootstrap.so",
        "libcheese-quest.so",
        "libcheese-snapdragon.so",
        "libpct-opace6.so",
        "libbinder54.so",
    ).map { jniLibsDir.file(it).asFile.absolutePath }
    commandLine(listOf(ndkStrip, "--strip-all") + targets)
    inputs.files(targets.map { File(it) })
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }.configureEach {
    dependsOn(stripNativePayloads)
}

dependencies {
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.core.ktx)
    implementation(libs.material)

    // Compose basics: backdrop exposes its Compose deps at runtime scope, so they have to be
    // declared here for compilation.
    implementation(libs.androidx.compose.runtime)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.foundation)

    // Liquid Glass button (Compose, also pulls in shapes)
    implementation(libs.kyant.backdrop)
    implementation(libs.kyant.shapes)

    // Wireless debugging pairing (SPAKE2 / HKDF / AES-GCM)
    implementation(libs.androidx.annotation)
    implementation(libs.bouncycastle.prov)
    implementation(libs.bouncycastle.pkix)
    // TLSv1.3 exportKeyingMaterial without relying on hidden APIs
    implementation(libs.conscrypt.android)

    // Shell transport that needs neither wireless debugging nor a computer: Shizuku hands the
    // app a process running as shell (uid 2000), which is exactly what the payloads expect.
    implementation(libs.shizuku.api)
    implementation(libs.shizuku.provider)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
}
