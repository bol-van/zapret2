#pragma once

// shim for old NDK and old gcc linux compilers

#if defined(__linux__)

#include <sys/syscall.h>

#if defined(__ANDROID__) && __ANDROID_API__ < 28 || !defined(SYS_getrandom)

#define NEED_GETRANDOM

#include <sys/types.h>

/* getrandom flags */
#define GRND_NONBLOCK	1
#define GRND_RANDOM	2

ssize_t getrandom(void *ptr, size_t len, unsigned int flags);

#else

#include <sys/random.h>

#endif

#elif defined(__CYGWIN__)

#include <sys/random.h>

#elif defined(__APPLE__)

#include <sys/random.h>

#endif
