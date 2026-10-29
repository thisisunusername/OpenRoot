/*
 * Loader for the runtime target profile. See include/target_profile.h for the file format.
 *
 * Parsing is done by hand rather than with a generated table so the failure message can name the
 * exact key that is missing: a profile with one typo should say which line is wrong, not just
 * "invalid profile".
 */
#include "target_profile.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct target_profile g_profile;
static bool g_loaded = false;

/* Every address key must be present; a profile is either complete or rejected. */
static const char *kAddressKeys[] = {
    "selinux_enforcing_offset",
    "memstart_addr_offset",
    "sysctl_table_root_offset",
    "proc_douintvec_offset",
    "init_task_offset",
    "init_cred_offset",
    "pipe_fop_offset",
    "tasks_offset",
    "pid_offset",
    "mm_offset",
    "real_cred_offset",
};

#define KEY_COUNT (sizeof(kAddressKeys) / sizeof(kAddressKeys[0]))

/* Which field a key names, or NULL when the key is unknown. */
static unsigned long *field_for(const char *key) {
    if (!strcmp(key, "selinux_enforcing_offset")) return &g_profile.selinux_enforcing_offset;
    if (!strcmp(key, "memstart_addr_offset")) return &g_profile.memstart_addr_offset;
    if (!strcmp(key, "sysctl_table_root_offset")) return &g_profile.sysctl_table_root_offset;
    if (!strcmp(key, "proc_douintvec_offset")) return &g_profile.proc_douintvec_offset;
    if (!strcmp(key, "init_task_offset")) return &g_profile.init_task_offset;
    if (!strcmp(key, "init_cred_offset")) return &g_profile.init_cred_offset;
    if (!strcmp(key, "pipe_fop_offset")) return &g_profile.pipe_fop_offset;
    if (!strcmp(key, "tasks_offset")) return &g_profile.tasks_offset;
    if (!strcmp(key, "pid_offset")) return &g_profile.pid_offset;
    if (!strcmp(key, "mm_offset")) return &g_profile.mm_offset;
    if (!strcmp(key, "real_cred_offset")) return &g_profile.real_cred_offset;
    return NULL;
}

/* Trim leading and trailing whitespace in place and return the new start. */
static char *trim(char *text) {
    while (*text && isspace((unsigned char)*text)) text++;
    if (!*text) return text;
    char *end = text + strlen(text) - 1;
    while (end > text && isspace((unsigned char)*end)) *end-- = '\0';
    return text;
}

/* Copies a value into a fixed buffer, refusing anything that would truncate. */
static int copy_value(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n == 0 || n >= cap) return -EINVAL;
    memcpy(dst, src, n + 1);
    return 0;
}

int tgt_load(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) return -errno;

    memset(&g_profile, 0, sizeof(g_profile));
    /* Whether each address key was seen, so the check at the end can name the absent ones. */
    bool seen[KEY_COUNT];
    memset(seen, 0, sizeof(seen));

    char line[512];
    int line_number = 0;
    int rc = 0;

    while (fgets(line, sizeof(line), file)) {
        line_number++;
        /* A `#` starts a comment anywhere on the line. */
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';

        char *text = trim(line);
        if (!*text) continue;

        char *eq = strchr(text, '=');
        if (!eq) {
            printf("[-] profile:%d: expected key = value\n", line_number);
            rc = -EINVAL;
            break;
        }
        *eq = '\0';
        char *key = trim(text);
        char *value = trim(eq + 1);

        if (!strcmp(key, "release")) {
            if ((rc = copy_value(g_profile.release, sizeof(g_profile.release), value)) != 0) {
                printf("[-] profile:%d: bad release\n", line_number);
                break;
            }
            continue;
        }
        if (!strcmp(key, "binder_device")) {
            if ((rc = copy_value(g_profile.binder_device, sizeof(g_profile.binder_device), value)) != 0) {
                printf("[-] profile:%d: bad binder_device\n", line_number);
                break;
            }
            continue;
        }

        unsigned long *field = field_for(key);
        if (!field) {
            printf("[-] profile:%d: unknown key \"%s\"\n", line_number, key);
            rc = -EINVAL;
            break;
        }

        /* Base 0 so a profile may write 0x2ba4000 or 45760512 and mean the same thing. */
        char *end = NULL;
        errno = 0;
        unsigned long parsed = strtoul(value, &end, 0);
        if (errno || end == value || (end && *end)) {
            printf("[-] profile:%d: \"%s\" is not a number\n", line_number, value);
            rc = -EINVAL;
            break;
        }
        *field = parsed;
        for (size_t i = 0; i < KEY_COUNT; i++) {
            if (!strcmp(key, kAddressKeys[i])) seen[i] = true;
        }
    }

    fclose(file);
    if (rc != 0) return rc;

    for (size_t i = 0; i < KEY_COUNT; i++) {
        if (!seen[i]) {
            printf("[-] profile: missing \"%s\"\n", kAddressKeys[i]);
            return -EINVAL;
        }
    }
    if (g_profile.binder_device[0] == '\0') {
        /* Every Android 5.4 device has at least one of the three nodes, and the caller passes an
         * explicit profile, so a default here would only hide a broken file. */
        printf("[-] profile: missing \"binder_device\"\n");
        return -EINVAL;
    }
    if (g_profile.release[0] == '\0') {
        printf("[-] profile: missing \"release\"\n");
        return -EINVAL;
    }

    g_loaded = true;
    return 0;
}

const struct target_profile *tgt(void) {
    return g_loaded ? &g_profile : NULL;
}

void tgt_dump(void) {
    if (!g_loaded) {
        printf("[-] no target profile loaded\n");
        return;
    }
    const struct target_profile *p = &g_profile;
    printf("[+] profile release=%s binder=%s\n", p->release, p->binder_device);
    printf("[+]   selinux_enforcing=+0x%lx init_task=+0x%lx init_cred=+0x%lx\n",
           p->selinux_enforcing_offset, p->init_task_offset, p->init_cred_offset);
    printf("[+]   memstart_addr=+0x%lx sysctl_table_root=+0x%lx pipe_fop=+0x%lx\n",
           p->memstart_addr_offset, p->sysctl_table_root_offset, p->pipe_fop_offset);
    printf("[+]   proc_douintvec=+0x%lx\n", p->proc_douintvec_offset);
    printf("[+]   task: tasks=+0x%lx pid=+0x%lx mm=+0x%lx real_cred=+0x%lx\n",
           p->tasks_offset, p->pid_offset, p->mm_offset, p->real_cred_offset);
}