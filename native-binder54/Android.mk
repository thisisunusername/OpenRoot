LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := binder54
LOCAL_CFLAGS += -Iinclude
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