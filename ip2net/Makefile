CC ?= cc
OPTIMIZE ?= -Os
CFLAGS_PIC = -fPIC
CFLAGS += -std=gnu99 $(OPTIMIZE)
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_WIN = -static
LDFLAGS_PIE = -pie

LIBS = 
LIBS_WIN = -lws2_32
SRC_FILES = ip2net.c qsort.c

all: ip2net

ip2net: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_PIC) -o ip2net $(SRC_FILES) $(LIBS) $(LDFLAGS) $(LDFLAGS_PIE)

systemd: ip2net

android: ip2net

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_PIC) $(CFLAGS_BSD) -o ip2net $(SRC_FILES) $(LIBS) $(LDFLAGS) $(LDFLAGS_PIE)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_PIC) $(CFLAGS_BSD) -o ip2neta $(SRC_FILES) -target arm64-apple-macos10.8 $(LIBS) $(LDFLAGS) $(LDFLAGS_PIE)
	$(CC) $(CFLAGS) $(CFLAGS_PIC) $(CFLAGS_BSD) -o ip2netx $(SRC_FILES) -target x86_64-apple-macos10.8 $(LIBS) $(LDFLAGS) $(LDFLAGS_PIE)
	strip ip2neta ip2netx
	lipo -create -output ip2net ip2netx ip2neta
	rm -f ip2netx ip2neta

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o ip2net.exe $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

win-arm64-cross:
	clang -s $(CFLAGS) $(CFLAGS_WIN) --sysroot=/clangarm64 --target=aarch64-w64-mingw32 -B/clang64/bin -rtlib=compiler-rt -o mdig.exe $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

clean:
	rm -f ip2net *.o
