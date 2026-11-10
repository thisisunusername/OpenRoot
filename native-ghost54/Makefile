API ?= 35

# Auto-detect NDK (same rules as ../native-or/Makefile).
ifeq ($(OS),Windows_NT)
  NDK_ROOT ?= $(subst \,/,$(or $(ANDROID_NDK_HOME),$(NDK_ROOT_ENV),D:/android-ndk-r27d))
  override NDK_ROOT := $(subst \,/,$(NDK_ROOT))
  PREBUILT := windows-x86_64
  EXT := .cmd
  STRIP_EXT := .exe
else
  NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),/opt/android-ndk-r27d)
  UNAME_S := $(shell uname -s)
  PREBUILT := $(if $(filter Darwin,$(UNAME_S)),darwin-x86_64,linux-x86_64)
  EXT :=
  STRIP_EXT :=
endif

NDK_BIN := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin
CC := $(NDK_BIN)/aarch64-linux-android$(API)-clang$(EXT)
STRIP := $(NDK_BIN)/llvm-strip$(STRIP_EXT)

BUILD_DIR ?= ../build/ghost54
OUT := $(BUILD_DIR)

# `ghostlock54` ships as `libghostlock54.so` so it lands in the APK's jniLibs: a `.so` is the only
# file type the packaging step installs verbatim without touching its bytes.
#
# No `-lselinux`: the NDK does not ship libselinux at all (its headers are AOSP-only), so the one
# call the payload needed — setcon() — is inlined over /proc/self/attr/current in ghostlock54.c.
#
# `-pthread` is not optional. The payload forks a child that keeps writing the log while the parent
# drives the kernel write, and the two share a mutex so lines do not interleave; without `-pthread`
# bionic resolves pthread_mutex_* to stubs that return ENOSYS and the log silently loses its tail.

TARGET := $(OUT)/libghostlock54.so
SRC := ghostlock54.c

CFLAGS := -O2 -fPIE -fPIC -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -pthread
LDFLAGS := -pie -pthread

all: $(TARGET)

$(TARGET): $(SRC) Makefile
	@test -d "$(NDK_BIN)" || { echo "NDK not found at $(NDK_ROOT)"; exit 1; }
	@mkdir -p "$(OUT)"
	$(CC) $(CFLAGS) -o "$(TARGET)" $(SRC) $(LDFLAGS)
	@# It re-execs itself after staging, so it has to stay runnable: strip --strip-unneeded only.
	$(STRIP) --strip-unneeded "$(TARGET)"
	@echo "built $(TARGET)"

clean:
	rm -f "$(TARGET)"

.PHONY: all clean