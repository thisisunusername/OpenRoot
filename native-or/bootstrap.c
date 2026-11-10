#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define BLKROSET   0x125d
/* Paths are supplied by the build so the same source can be staged anywhere. */
#ifndef KSUD_STAGE
#define KSUD_STAGE "/data/local/tmp/openroot/ksud"
#endif
#ifndef KSUD
#define KSUD       "/data/adb/ksud"
#endif
#ifndef PREFS_PATH
#define PREFS_PATH "/data/local/tmp/openroot/openroot.xml"
#endif
#ifndef MODULES_DIR
#define MODULES_DIR "/data/adb/modules"
#endif
/* Magisk fallback: used only after ksud refuses to late-load. MAGISKINIT_STAGE is the
 * magiskinit binary staged by the app, MAGISK_STAGE the directory its payload lives in. */
#ifndef MAGISKINIT_STAGE
#define MAGISKINIT_STAGE "/data/local/tmp/openroot/magiskinit"
#endif
#ifndef MAGISK_STAGE
#define MAGISK_STAGE "/data/local/tmp/openroot/magisk"
#endif

/* Root command channel: when no SU manager is used, a detached daemon keeps running as root and
 * executes whatever command the app writes to ROOT_CMD_FILE, dropping the output in ROOT_CMD_OUT. */
#define ROOT_CMD_DIR  "/data/local/tmp/openroot"
#define ROOT_CMD_FILE ROOT_CMD_DIR "/cmd"
#define ROOT_CMD_OUT  ROOT_CMD_DIR "/out"
#define ROOT_CMD_DONE ROOT_CMD_DIR "/done"

static void run_root_command_daemon(void)
{
    pid_t pid = fork();
    if (pid != 0)
        return;
    setsid();
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, 0);
        dup2(devnull, 1);
        dup2(devnull, 2);
        close(devnull);
    }
    unlink(ROOT_CMD_DONE);
    for (;;) {
        if (access(ROOT_CMD_FILE, F_OK) == 0) {
            char line[512];
            snprintf(line, sizeof(line),
                     "/system/bin/sh %s > %s 2>&1; mv %s %s",
                     ROOT_CMD_FILE, ROOT_CMD_OUT, ROOT_CMD_FILE, ROOT_CMD_DONE);
            if (system(line) != 0)
                unlink(ROOT_CMD_FILE);
        }
        usleep(200000);
    }
}

static int pref_true(const char *buf, const char *key)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "name=\"%s\"", key);
    char *p = strstr(buf, needle);
    if (!p) return 0;
    char *tag_end = strchr(p, '>');
    char *v = strstr(p, "value=\"true\"");
    return v && tag_end && v < tag_end;
}

static int read_prefs(char *su_manager, size_t su_manager_size, int *soft_reboot,
                      int *disable_modules)
{
    int fd = open(PREFS_PATH, O_RDONLY);
    if (fd < 0) return -1;

    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *p = strstr(buf, "name=\"su_manager\">");
    if (!p) return -1;
    p += strlen("name=\"su_manager\">");
    char *end = strchr(p, '<');
    if (!end) return -1;
    size_t len = end - p;
    if (len == 0 || len >= su_manager_size) return -1;
    memcpy(su_manager, p, len);
    su_manager[len] = '\0';

    *soft_reboot = pref_true(buf, "soft_reboot");
    *disable_modules = pref_true(buf, "disable_modules");

    return 0;
}

static int adopt_zygote_env(void)
{
    FILE *f = popen("pidof zygote64 zygote", "r");
    if (!f) return -1;
    int pid = 0;
    fscanf(f, "%d", &pid);
    pclose(f);
    if (!pid) return -1;

    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    static char buf[16384];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    for (char *p = buf, *end = buf + n; p < end; p += strlen(p) + 1)
        putenv(p);
    return 0;
}

static int should_ro(const char *name)
{
    size_t len = strlen(name);
    if (!strcmp(name, "super"))  return 1;
    if (!strcmp(name, "misc"))   return 1;
    if (!strcmp(name, "steady")) return 1;
    if (len >= 2 && name[len - 2] == '_' &&
        (name[len - 1] == 'a' || name[len - 1] == 'b'))
        return 1;
    return 0;
}

static int set_partitions_ro(void)
{
    DIR *dir = opendir("/dev/block/by-name");
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!should_ro(ent->d_name))
            continue;

        char path[128];
        snprintf(path, sizeof(path), "/dev/block/by-name/%s", ent->d_name);

        int fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;

        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)) {
            int on = 1;
            ioctl(fd, BLKROSET, &on);
        }
        close(fd);
    }

    closedir(dir);
    return 0;
}

static int late_load_running(void)
{
    DIR *d = opendir("/proc");
    if (!d)
        return 0;
    struct dirent *e;
    char path[64], buf[256];
    int found = 0;
    while ((e = readdir(d)) != NULL) {
        char *end;
        strtol(e->d_name, &end, 10);
        if (*end) continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';
        for (int i = 0; i < n; i++)
            if (!buf[i]) buf[i] = ' ';
        if (strstr(buf, "ksud") && strstr(buf, "late-load")) {
            found = 1;
            break;
        }
    }
    closedir(d);
    return found;
}

/* Brings up a Magisk payload in place of KernelSU.
 *
 * This is the second rung of the ladder: the kernel bug already gave us uid 0, but `ksud late-load`
 * refused (usually because no matching `openroot-android*-*.ko` ships for this kernel). Instead of
 * dropping straight to a command channel, magiskinit is exec'd from the staged copy and left to set
 * up its own rootfs. It runs in the init context we already switched to, which is what it expects.
 *
 * Returns 0 when `/sbin/su` (Magisk's own marker) exists afterwards, which is the same signal
 * mtk-easy-su uses to declare success.
 */

static int run_ctx(const char *ctx, char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (ctx) {
            int fd = open("/proc/self/attr/exec", O_WRONLY);
            if (fd >= 0) { write(fd, ctx, strlen(ctx)); close(fd); }
        }
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int try_magisk_fallback(void)
{
    if (access(MAGISKINIT_STAGE, X_OK) != 0)
        return -1;

    /* magiskinit wants to be PID 1 in its own mount namespace to mirror the real boot; a plain exec
     * is enough here because we only need `su` from this boot's payload. */
    int rc = run_ctx(NULL, (char *[]){
        MAGISKINIT_STAGE, "--magiskdir", MAGISK_STAGE, NULL
    });

    /* magiskinit's exit code is not trustworthy across versions, so the marker decides. */
    if (access("/sbin/su", X_OK) == 0)
        return 0;
    return rc == 0 ? 0 : -1;
}

static void touch(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd >= 0)
        close(fd);
}

/* Mark every installed module disabled before ksud runs. A broken module
 * otherwise loads on the next boot and bootloops the device. */
static int disable_modules(void)
{
    DIR *dir = opendir(MODULES_DIR);
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.')
            continue;
        char path[256];
        snprintf(path, sizeof(path), MODULES_DIR "/%s/disable", ent->d_name);
        touch(path);
    }
    closedir(dir);
    return 0;
}

int main(void)
{
    touch("/dev/dfm1");
    char su_manager[256];
    int soft_reboot, disable_mods;
    if (read_prefs(su_manager, sizeof(su_manager), &soft_reboot, &disable_mods) != 0) {
        touch("/dev/dfme0");
        return 1;
    }

    /* "none" means the user asked for a root command channel instead of a manager. */
    if (strcmp(su_manager, "none") == 0) {
        run_root_command_daemon();
        return 0;
    }

    touch("/dev/dfm2");
    if (adopt_zygote_env())
        touch("/dev/dfmw0");

    touch("/dev/dfm3");
    if (set_partitions_ro())
        touch("/dev/dfmw1");

    if (disable_mods) {
        touch("/dev/dfm4");
        if (disable_modules()) {
            touch("/dev/dfme1");
            return 1;
        }
    }

    touch("/dev/dfm5");
    // ksu only allows init to switch to ksud context and we are in kernel context now
    // once ksu starts, selinux is enforcing, but here its still permissive
    // switch our context while we still can
    pid_t pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        int fd = open("/proc/self/attr/current", O_WRONLY);
        if (fd >= 0) {
            const char *ctx = "u:r:init:s0";
            write(fd, ctx, strlen(ctx));
            close(fd);
        }
        if (run_ctx(NULL, (char *[]){ KSUD_STAGE, "late-load", "--package-name", su_manager, NULL }) == 0) {
            touch("/dev/dfm6");
            if (soft_reboot) {
                while (late_load_running()) sleep(1);
                run_ctx("u:r:ksu:s0", (char *[]){ KSUD, "soft-reboot", NULL });
            }
        } else if (try_magisk_fallback() == 0) {
            /* No matching openroot-android*-*.ko for this kernel, so KernelSU is unavailable. The
             * uid 0 we got is still good, so use it to bring up Magisk instead of giving up: a
             * Magisk payload reaches the user as a working `su` plus a manager, which is a much
             * better outcome than a bare command channel. */
            touch("/dev/dfme2");
            touch("/dev/dfmg1");
            if (soft_reboot) {
                while (late_load_running()) sleep(1);
                run_ctx("u:r:ksu:s0", (char *[]){ KSUD, "soft-reboot", NULL });
            }
        } else {
            touch("/dev/dfme2");
            /* KernelSU refused to load and there was no Magisk payload to fall back on, but the root
             * we just got is still valid for this boot. Keep the command channel instead of throwing
             * it away, so the user can run commands (and retry the late-load) by hand. */
            run_root_command_daemon();
            touch("/dev/dfm7");
        }
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);

    return 0;
}
