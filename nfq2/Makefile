CC ?= cc
PKG_CONFIG ?= pkg-config
OPTIMIZE ?= -Os
MINSIZE ?= -flto=auto -ffunction-sections -fdata-sections
CFLAGS += -std=gnu99 $(OPTIMIZE) $(MINSIZE)
CFLAGS_PIC = -fPIC
CFLAGS_LINUX = -Wno-alloc-size-larger-than $(CFLAGS_PIC)
CFLAGS_SYSTEMD = -DUSE_SYSTEMD
CFLAGS_BSD = -Wno-address-of-packed-member $(CFLAGS_PIC)
CFLAGS_DARWIN = $(CFLAGS_BSD)
CFLAGS_CYGWIN = -Wno-address-of-packed-member -static -Wl,--nxcompat
CFLAGS_CYGWIN32 =
CFLAGS_CYGWIN64 = -Wl,--dynamicbase -Wl,--high-entropy-va
CFLAGS_UBSAN = -fsanitize=undefined,alignment -fno-sanitize-recover=undefined,alignment
LDFLAGS_PIE = -pie
LDFLAGS += -flto=auto -Wl,--gc-sections $(LDFLAGS_PIE)
LDFLAGS_DARWIN = -flto=auto -Wl,-dead_strip
LDFLAGS_ANDROID = -llog
LDFLAGS_CYGWIN = -Wl,--build-id=none
STRIPP=-s
LIBS =
LIBS_LINUX = -lz -lnetfilter_queue -lnfnetlink -lmnl -lm
LIBS_SYSTEMD = -lsystemd
LIBS_BSD = -lz -lm
LIBS_CYGWIN = -lz -Lwindows/windivert -Iwindows -lole32 -loleaut32 -liphlpapi -lntdll
LIBS_CYGWIN32 = -lwindivert32
LIBS_CYGWIN64 = -lwindivert64
RES_CYGWIN32 = windows/res/winws_res32.o
RES_CYGWIN64 = windows/res/winws_res64.o
SRC_FILES = *.c crypto/*.c
DARWIN_ENGINE_SRC_FILES = zapret2_engine.c zapret2_defaults.c zapret2_profiles.c zapret2_config.c zapret2_options.c params.c helpers.c hostlist.c ipset.c pools.c filter.c protocol.c darkmagic.c desync.c conntrack.c packet_queue.c lua.c timer.c sec.c random.c gzip.c checksum.c crypto/*.c
SRC_FILES_ANDROID = $(SRC_FILES) andr/*.c

LUA_JIT?=1

ifeq ($(LUA_JIT),1)

LUAJIT_VER?=2.1
LUAJIT_LUA_VER?=5.1
LUA_PKG:=luajit
CFLAGS_CYGWIN32 = -msse2 -mfpmath=sse

$(info trying luajit $(LUAJIT_VER) lua $(LUAJIT_LUA_VER))

LUA_LIB_NAME=
ifeq ($(LUA_CFLAGS),)
 LUA_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(LUA_PKG) 2>/dev/null)
 ifeq ($(LUA_CFLAGS),)
  LUA_CFLAGS := -I/usr/local/include/luajit-$(LUAJIT_VER) -I/usr/include/luajit-$(LUAJIT_VER)
 endif
endif
ifeq ($(LUA_LIB),)
 LUA_LIB := $(shell $(PKG_CONFIG) --libs $(LUA_PKG) 2>/dev/null)
 LUA_LIB_DIR :=

 ifeq ($(LUA_LIB),)
  ifneq ($(wildcard /usr/local/lib/libluajit-$(LUAJIT_LUA_VER).*),)
   LUA_LIB_NAME:=luajit-$(LUAJIT_LUA_VER)
   LUA_LIB_DIR:=/usr/local/lib
  else ifneq ($(wildcard /usr/lib/libluajit-$(LUAJIT_LUA_VER).*),)
   LUA_LIB_NAME:=luajit-$(LUAJIT_LUA_VER)
  endif
  ifeq ($(LUA_LIB_NAME),)
   $(info could not find luajit lib name)
   LUA_LIB:=
   LUA_CFLAGS:=
  else
   ifneq ($(LUA_LIB_DIR),)
    LUA_LIB = -L$(LUA_LIB_DIR)
   endif
   LUA_LIB += -l$(LUA_LIB_NAME)
  endif
 endif
endif

LUA_CFL := -DLUAJIT

else

LUA_CFL :=

endif



ifeq ($(LUA_LIB),)

# no success with luajit

LUA_VER?=5.5
LUA_VER_UNDOTTED:=$(shell echo $(LUA_VER) | sed 's/\.//g')

LUA_CFL :=

$(info trying lua $(LUA_VER))

OSNAME := $(shell uname)
ifeq ($(OSNAME),FreeBSD)
 LUA_PKG:=lua-$(LUA_VER)
else
 LUA_PKG:=lua$(LUA_VER_UNDOTTED)
endif

ifeq ($(LUA_CFLAGS),)
 LUA_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(LUA_PKG) 2>/dev/null)
 ifeq ($(LUA_CFLAGS),)
  LUA_CFLAGS := -I/usr/local/include/lua$(LUA_VER) -I/usr/local/include/lua-$(LUA_VER) -I/usr/include/lua$(LUA_VER) -I/usr/include/lua-$(LUA_VER) -I/usr/local/include/lua -I/usr/local/include
 endif
endif
ifeq ($(LUA_LIB),)
 LUA_LIB := $(shell $(PKG_CONFIG) --libs $(LUA_PKG) 2>/dev/null)
 LUA_LIB_DIR :=
 ifeq ($(LUA_LIB),)
  ifneq ($(wildcard /usr/local/lib/liblua-$(LUA_VER).*),)
   LUA_LIB_NAME:=lua-$(LUA_VER)
   LUA_LIB_DIR:=/usr/local/lib
  else ifneq ($(wildcard /usr/local/lib/liblua$(LUA_VER).*),)
   LUA_LIB_NAME:=lua$(LUA_VER)
   LUA_LIB_DIR:=/usr/local/lib
  else ifneq ($(wildcard /usr/local/lib/liblua.*),)
   LUA_LIB_NAME:=lua
   LUA_LIB_DIR:=/usr/local/lib
  else ifneq ($(wildcard /usr/lib/liblua-$(LUA_VER).*),)
   LUA_LIB_NAME:=lua-$(LUA_VER)
  else ifneq ($(wildcard /usr/lib/liblua$(LUA_VER).*),)
   LUA_LIB_NAME:=lua$(LUA_VER)
  else ifneq ($(wildcard /usr/lib/liblua.*),)
   LUA_LIB_NAME:=lua
  endif
  ifeq ($(LUA_LIB_NAME),)
   $(error could not find lua lib name)
  endif
  ifneq ($(LUA_LIB_DIR),)
   LUA_LIB = -L$(LUA_LIB_DIR)
  endif
  LUA_LIB += -l$(LUA_LIB_NAME)
 endif
endif

endif


LUA_CFL += $(LUA_CFLAGS)


all: nfqws2

nfqws2: $(SRC_FILES)
	$(CC) $(STRIPP) $(CFLAGS) $(LUA_CFL) $(CFLAGS_LINUX) -o nfqws2 $(SRC_FILES) $(LIBS) $(LUA_LIB) $(LIBS_LINUX) $(LDFLAGS)

ubsan: $(SRC_FILES)
	$(CC) $(CFLAGS_UBSAN) $(CFLAGS) $(LUA_CFL) $(CFLAGS_LINUX) -o nfqws2 $(SRC_FILES) $(LIBS) $(LUA_LIB) $(LIBS_LINUX) $(LDFLAGS)

systemd: $(SRC_FILES)
	$(CC) $(STRIPP) $(CFLAGS) $(LUA_CFL) $(CFLAGS_LINUX) $(CFLAGS_SYSTEMD) -o nfqws2 $(SRC_FILES) $(LIBS) $(LUA_LIB) $(LIBS_LINUX) $(LIBS_SYSTEMD) $(LDFLAGS)

android: $(SRC_FILES_ANDROID)
	$(CC) $(STRIPP) $(CFLAGS) $(LUA_CFL) -o nfqws2 $(SRC_FILES_ANDROID) $(LIBS) $(LUA_LIB) $(LIBS_LINUX) $(LDFLAGS) $(LDFLAGS_ANDROID)

bsd: $(SRC_FILES)
	$(CC) $(STRIPP) $(CFLAGS) $(LUA_CFL) $(CFLAGS_BSD) -o dvtws2 $(SRC_FILES) $(LIBS) $(LUA_LIB) $(LIBS_BSD) $(LDFLAGS)

darwin: $(SRC_FILES)
	$(CC) $(STRIPP) $(CFLAGS) $(LUA_CFL) $(CFLAGS_DARWIN) -o dvtws2 $(SRC_FILES) $(LIBS) $(LUA_LIB) $(LIBS_BSD) $(LDFLAGS_DARWIN)

darwin-engine-check: $(SRC_FILES)
	$(CC) -fsyntax-only $(CFLAGS) $(LUA_CFL) $(CFLAGS_DARWIN) $(SRC_FILES)

libzapret2core-darwin.a: $(DARWIN_ENGINE_SRC_FILES)
	mkdir -p build/darwin-engine
	rm -f $@
	objs=""; for src in $(DARWIN_ENGINE_SRC_FILES); do obj="build/darwin-engine/$${src%.c}.o"; mkdir -p "$$(dirname "$$obj")"; $(CC) -c $(CFLAGS) $(LUA_CFL) $(CFLAGS_DARWIN) "$$src" -o "$$obj"; objs="$$objs $$obj"; done; ar rcs $@ $$objs

cygwin64:
	$(CC) $(STRIPP) $(CFLAGS) $(LUA_CFL) $(CFLAGS_CYGWIN) $(CFLAGS_CYGWIN64) -o winws2 $(SRC_FILES) $(RES_CYGWIN64) $(LIBS) $(LUA_LIB) $(LIBS_CYGWIN) $(LIBS_CYGWIN64) $(LDFLAGS) $(LDFLAGS_CYGWIN)
cygwin32:
	$(CC) $(STRIPP) $(CFLAGS) $(LUA_CFL) $(CFLAGS_CYGWIN) $(CFLAGS_CYGWIN32) -o winws2 $(SRC_FILES) $(RES_CYGWIN32) $(LIBS) $(LUA_LIB) $(LIBS_CYGWIN) $(LIBS_CYGWIN32) $(LDFLAGS) $(LDFLAGS_CYGWIN)
cygwin: cygwin64

clean:
	rm -f nfqws2 dvtws2 winws2.exe libzapret2core-darwin.a
	rm -rf build/darwin-engine
