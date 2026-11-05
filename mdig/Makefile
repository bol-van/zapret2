CC ?= cc
OPTIMIZE ?= -Os
CFLAGS_PIC = -fPIC
CFLAGS += -std=gnu99 $(OPTIMIZE)
CFLAGS_BSD = -Wno-address-of-packed-member
CFLAGS_WIN = -static
LDFLAGS_PIE = -pie
LIBS = -lpthread
LIBS_ANDROID =
LIBS_WIN = -lws2_32 -lpthread
SRC_FILES = *.c

all: mdig

mdig: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_PIC) -o mdig $(SRC_FILES) $(LIBS) $(LDFLAGS) $(LDFLAGS_PIE)

systemd: mdig

android: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_PIC) -o mdig $(SRC_FILES) $(LIBS_ANDROID) $(LDFLAGS) $(LDFLAGS_PIE)

bsd: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_PIC) $(CFLAGS_BSD) -o mdig $(SRC_FILES) $(LIBS) $(LDFLAGS) $(LDFLAGS_PIE)

mac: $(SRC_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_PIC) $(CFLAGS_BSD) -o mdiga $(SRC_FILES) -target arm64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS) $(LDFLAGS_PIE)
	$(CC) $(CFLAGS) $(CFLAGS_PIC) $(CFLAGS_BSD) -o mdigx $(SRC_FILES) -target x86_64-apple-macos10.8 $(LIBS_BSD) $(LDFLAGS) $(LDFLAGS_PIE)
	strip mdiga mdigx
	lipo -create -output mdig mdigx mdiga
	rm -f mdigx mdiga

win: $(SRC_FILES)
	$(CC) -s $(CFLAGS) $(CFLAGS_WIN) -o mdig.exe $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

win-arm64-cross:
	clang -s $(CFLAGS) $(CFLAGS_WIN) --sysroot=/clangarm64 --target=aarch64-w64-mingw32 -B/clang64/bin -rtlib=compiler-rt -o mdig.exe $(SRC_FILES) $(LIBS_WIN) $(LDFLAGS)

clean:
	rm -f mdig *.o
