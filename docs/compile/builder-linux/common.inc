EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

CURL_OPT="--connect-timeout 5 --max-time 120 --retry 5 --retry-delay 30"

TOOLCHAINS="$EXEDIR/toolchain"
DEPS="$EXEDIR/deps"
STAGE="$EXEDIR/staging"
OPTIMIZE=${OPTIMIZE:--Oz}
#MINSIZE="${MINSIZE:--flto=auto -ffunction-sections -fdata-sections}"
MINSIZE="${MINSIZE:--ffunction-sections -fdata-sections}"
LDMINSIZE="${LDMINSIZE:--Wl,--gc-sections -flto=auto}"
#CFLAGS=""
LDFLAGS="-lgcc_eh $LDFLAGS"
# PIE makes ASLR working but adds 5% to size
# PIE does not work for arm32 and all mips
PIE=${PIE:-0}
HOSTCC=${HOSTCC:-cc}
ZLIB_VER=${ZLIB_VER:-1.3.2}
ZLIB_NG_VER=${ZLIB_NG_VER:-2.3.3}
LUA_VER=${LUA_VER:-5.5}
LUA_RELEASE=${LUA_RELEASE:-5.5.1}
LUAJIT_VER=${LUAJIT_VER:-2.1}
LUAJIT_RELEASE=${LUAJIT_RELEASE:-2.1-20250826}
LUAJIT_LUA_VER=${LUAJIT_LUA_VER:-5.1}
nproc=$(nproc)

TARGETS="\
aarch64-unknown-linux-musl \
arm-buildroot-linux-musleabi \
armv6-unknown-linux-musleabi \
i586-unknown-linux-musl \
x86_64-unknown-linux-musl \
mips-unknown-linux-muslsf \
mips64-unknown-linux-musl \
mips64el-unknown-linux-musl \
mipsel-unknown-linux-muslsf \
powerpc-unknown-linux-musl \
riscv64-unknown-linux-musl \
"

target_has_luajit()
{
	case "$1" in
		aarch64-unknown-linux-musl| \
		armv6-unknown-linux-musleabi| \
		x86_64-unknown-linux-musl| \
		mips-unknown-linux-muslsf| \
		mips64-unknown-linux-musl| \
		mips64el-unknown-linux-musl| \
		mipsel-unknown-linux-muslsf| \
		powerpc-unknown-linux-musl) \
			return 0
			;;
	esac
	return 1
}

REQD_H_FILES="/usr/include/sys/capability.h /usr/include/bits/libc-header-start.h"
REQD_QUEUE_1="/usr/include/sys/queue.h"
REQD_QUEUE_2="/usr/include/x86_64-linux-gnu/sys/queue.h"
check_h_files()
{
	[ ! -f "$REQD_QUEUE_1" -a ! -f  "$REQD_QUEUE_2" ] && {
		echo "could not find $REQD_QUEUE_1 or $REQD_QUEUE_2"
		help_pkg
		exit 10
	}
	check_file $REQD_H_FILES
}
install_h_files()
{
	if [ -f "$REQD_QUEUE_1" ]; then
		install -Dm644 -t $STAGING_DIR/include/sys $REQD_QUEUE_1
	elif [ -f "$REQD_QUEUE_2" ]; then
		install -Dm644 -t $STAGING_DIR/include/sys $REQD_QUEUE_2
	fi
	install -Dm644 -t $STAGING_DIR/include/sys $REQD_H_FILES
}

buildenv()
{
	# $1 = arch

	export TARGET=$1
	export CC=$TARGET-gcc
	export LD=$TARGET-ld
	export AR=$TARGET-ar
	export NM=$TARGET-nm
	export STRIP=$TARGET-strip
	export STAGING_DIR="$EXEDIR/staging/$TARGET"
	[ -d "$STAGING_DIR" ] || {
		mkdir -p "$STAGING_DIR"
		mkdir -p "$STAGING_DIR/lib/pkgconfig"
		mkdir -p "$STAGING_DIR/bin"
		mkdir -p "$STAGING_DIR/include"
	}
	export PKG_CONFIG_PATH=$STAGING_DIR/lib/pkgconfig
	OLDPATH="$PATH"
	export PATH="$PATH:$TOOLCHAINS/$TARGET/bin"

	CPU=
	CFLAGS_PIC=
	LDFLAGS_PIE=-static
	# not all archs support -static-pie. if does not support - it produces dynamic executable
	# "-static -static-pie" causes segfaults
	case $1 in
		arm-buildroot-linux-musleabi)
			CPU="-mcpu=xscale -msoft-float"
			CFLAGS="$CPU $CFLAGS"
			;;
		armv6-*)
			CPU="-mthumb -msoft-float"
			CFLAGS="$CPU $CFLAGS"
			;;
		mips*)
			;;
		*)
			[ "$PIE" = 1 ] && {
				CFLAGS_PIC=-fPIC
				LDFLAGS_PIE="-static-pie"
			}
	esac
}

buildenv_clear()
{
	export PATH="$OLDPATH" TARGET= CC= LD= AR= NM= STRIP= STAGING_DIR= PKG_CONFIG_PATH=
	OLDPATH=
}

which()
{
	# on some systems 'which' command is considered deprecated and not installed by default
	# 'command -v' replacement does not work exactly the same way. it outputs shell aliases if present
	# $1 - executable name
	local IFS=:
	[ "$1" != "${1#/}" ] && [ -x "$1" ] && {
		echo "$1"
		return 0
	}
	for p in $PATH; do
	    [ -x "$p/$1" ] && {
		echo "$p/$1"
		return 0
	    }
	done
	return 1
}
exists()
{
	which "$1" >/dev/null 2>/dev/null
}
exists_dir()
{
	# use $1, ignore other args
	[ -d "$1" ]
}

dir_is_not_empty()
{
	# $1 - directory
	local n
	[ -d "$1" ] || return 1
	n=$(ls -A "$1" | wc -c | xargs)
	[ "$n" != 0 ]
}

find_str_in_list()
{
	# $1 - string
	# $2 - space separated values
	local v
	[ -n "$1" ] && {
		for v in $2; do
			[ "$v" = "$1" ] && return 0
		done
	}
	return 1
}

ask_list()
{
	# $1 - mode var
	# $2 - space separated value list
	# $3 - (optional) default value
	local M_DEFAULT
	eval M_DEFAULT="\$$1"
	local M_DEFAULT_VAR="$M_DEFAULT"
	local M="" m

	[ -n "$3" ] && { find_str_in_list "$M_DEFAULT" "$2" || M_DEFAULT="$3" ;}

	n=1
	for m in $2; do
		echo $n : $m
		n=$(($n+1))
	done
	printf "your choice (default : $M_DEFAULT) : "
	read m
	[ -n "$m" ] && M=$(echo $2 | cut -d ' ' -f$m 2>/dev/null)
	[ -z "$M" ] && M="$M_DEFAULT"
	echo selected : $M
	eval $1="\"$M\""

	[ "$M" != "$M_DEFAULT_VAR" ]
}

ask_target()
{
	# $1 = 1 = ask all, otherwise ask only present toolchains

	# already set ?
	[ -n "$TGT" ] && return

	local d ALL_TARGETS
	[ "$1" = 1 ] || {
		if dir_is_not_empty "$TOOLCHAINS"; then
			for d in "$TOOLCHAINS"/*; do
				[ -d "$d" ] && {
					d="$(basename "$d")"
					ALL_TARGETS="$ALL_TARGETS $d"
				}
			done
		fi
	}
	[ -n "$ALL_TARGETS" ] || ALL_TARGETS="$TARGETS"

	echo "select target :"
	ask_list TARGET "ALL $ALL_TARGETS" "ALL"
	echo
	echo selected TARGET : $TARGET
	echo

	if [ $TARGET = ALL ]; then
		TGT="$ALL_TARGETS"
	else
		TGT="$TARGET"
	fi
}

check_toolchains()
{
	dir_is_not_empty "$TOOLCHAINS" || {
		echo DOWNLOAD TOOLCHAINS FIRST
		exit 1
	}
}

help_pkg()
{
	echo "debian/ubuntu: apt install curl xz-utils bzip2 unzip make gcc gcc-multilib libc6-dev libcap-dev pkg-config"
	echo "fedora: dnf install curl xz bzip2 unzip make gcc glibc-devel glibc-devel.i686 libcap-devel pkg-config"
}

check_prog()
{
	while [ -n "$1" ]; do
		exists $1 || {
			echo $1 is not available
			help_pkg
			exit 10
		}
		shift
	done
}
check_file()
{
	while [ -n "$1" ]; do
		[ -f "$1" ] || {
			echo $1 is not available
			help_pkg
			exit 10
		}
		shift
	done
}

translate_target()
{
	case $1 in
		arm-buildroot-linux-musleabi)
			ZBINTARGET=linux-arm_xscale
			;;
		aarch64-unknown-linux-musl)
			ZBINTARGET=linux-arm64
			;;
		armv6-unknown-linux-musleabi)
			ZBINTARGET=linux-arm
			;;
		x86_64-unknown-linux-musl)
			ZBINTARGET=linux-x86_64
			;;
		i586-unknown-linux-musl)
			ZBINTARGET=linux-x86
			;;
		mips-unknown-linux-muslsf)
			ZBINTARGET=linux-mips
			;;
		mipsel-unknown-linux-muslsf)
			ZBINTARGET=linux-mipsel
			;;
		mips64-unknown-linux-musl)
			ZBINTARGET=linux-mips64
			;;
		mips64el-unknown-linux-musl)
			ZBINTARGET=linux-mipsel64
			;;
		powerpc-unknown-linux-musl)
			ZBINTARGET=linux-ppc
			;;
		riscv64-unknown-linux-musl)
			ZBINTARGET=linux-riscv64
			;;
		*)
			return 1
	esac
	return 0
}
