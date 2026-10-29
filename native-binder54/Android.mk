LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := binder54
LOCAL_CFLAGS += -Iinclude
# The payload is a 2019 PoC written against a looser clang. The checks below are off because the
# source predates them, not because the code is wrong: binder_uintptr_t is a u64 on arm64 and so
# is a pointer, and the struct callbacks are cast to the right signature at their one call site.
# -Wimplicit-function-declaration is deliberately NOT disabled: missing prototypes were real bugs
# in this tree (a truncated pthread_t would have crashed), and the prototypes are now in the
# headers instead of being papered over.
LOCAL_CFLAGS += -Wno-int-conversion
LOCAL_CFLAGS += -Wno-incompatible-function-pointer-types
LOCAL_CFLAGS += -Wno-implicit-int
LOCAL_CFLAGS += -Wno-int-to-pointer-cast
LOCAL_CFLAGS += -Wno-pointer-to-int-cast
LOCAL_CFLAGS += -Wno-deprecated-non-prototype
LOCAL_CFLAGS += -Wno-format
LOCAL_SRC_FILES := \
    src/exploit.c \
    src/endpoint.c \
    src/pending_node.c \
    src/binder.c \
    src/log.c \
    src/helpers.c \
    src/binder_lookup.c \
    src/realloc.c \
    src/node.c \
    src/target_profile.c \
    src/offset_dump.c
include $(BUILD_EXECUTABLE)