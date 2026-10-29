/*
 * Recovering a target profile from a device that currently has root.
 *
 * The whole reason these offsets have to be per build is that they are addresses inside one kernel
 * image. Anyone who reaches uid 0 on a device can read them straight out of the kernel's own symbol
 * table, so the practical way to get a profile is: run the exploit once, and while the temporary
 * root is still alive, dump the offsets into a file. Every later device on the same firmware then
 * reuses that file instead of exploiting blind.
 *
 * Two paths are supported, in this order:
 *
 *   1. /proc/kallsyms. With uid 0 and kptr_restrict not blocking, it lists every symbol with its
 *      runtime address. Subtracting the image base gives the offsets this profile wants. This is
 *      exact, and it also covers symbols the other path has to approximate.
 *
 *   2. The live read primitive. When kallsyms is restricted, the caller passes a reader and the
 *      offsets are recovered by following pointers from a known anchor. This is how the exploit
 *      itself finds its way around, so it needs no extra privileges - only the primitive.
 *
 * The output is the same `key = value` text `tgt_load` accepts, plus the struct member offsets,
 * which are read out of the running kernel rather than guessed.
 */
#ifndef OFFSET_DUMP_H
#define OFFSET_DUMP_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Reads `width` bytes at a kernel address. Supplied by the caller so this file does not depend on
 * how the primitive is implemented.
 */
typedef bool (*kernel_reader_fn)(uint64_t address, void *out, unsigned width);

/*
 * Writes a profile derived for `release` to `path`.
 *
 * `kernel_base` is the load address of the kernel image, which the exploit already computes from a
 * leaked `file_operations` pointer. `reader` may be NULL when kallsyms is usable; it is required
 * when it is not.
 *
 * `init_task` and `binder_device` are carried over from the profile that was used to get here, since
 * the running exploit already resolved them.
 *
 * Returns 0 on success and a negative value on failure. A partially written file is removed, so a
 * failed dump never leaves a profile behind that would be loaded as if it were complete.
 */
int dump_profile(const char *path,
                 const char *release,
                 uint64_t kernel_base,
                 uint64_t init_task_address,
                 uint64_t init_cred_address,
                 const char *binder_device,
                 kernel_reader_fn reader);

#endif