#define _GNU_SOURCE

#include "helpers.h"
#include "random.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <libgen.h>
#include <limits.h>
#include <errno.h>
#include <sys/param.h>

#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif


#define UNIQ_SORT \
{ \
	size_t i, j, u; \
	for (i = j = 0; j < ct; i++) \
	{ \
		u = pu[j++]; \
		for (; j < ct && pu[j] == u; j++); \
		pu[i] = u; \
	} \
	return i; \
}

int unique_size_t(size_t *pu, int ct) UNIQ_SORT
int unique_ssize_t(ssize_t *pu, int ct) UNIQ_SORT

static int cmp_size_t(const void * a, const void * b)
{
	return *(const size_t*)a < *(const size_t*)b ? -1 : *(const size_t*)a > *(const size_t*)b;
}
void qsort_size_t(size_t *array, int ct)
{
	qsort(array, ct, sizeof(*array), cmp_size_t);
}
static int cmp_ssize_t(const void * a, const void * b)
{
	return *(const ssize_t*)a < *(const ssize_t*)b ? -1 : *(const ssize_t*)a > *(const ssize_t*)b;
}
void qsort_ssize_t(ssize_t *array, int ct)
{
	qsort(array, ct, sizeof(*array), cmp_ssize_t);
}

int str_index(const char **strs, int count, const char *str)
{
	for (int i = 0; i < count; i++)
		if (!strcmp(strs[i], str)) return i;
	return -1;
}

void rtrim(char *s)
{
	if (s)
		for (char *p = s + strlen(s) - 1; p >= s && (*p == '\n' || *p == '\r'); p--) *p = '\0';
}

void replace_char(char *s, char from, char to)
{
	for (; *s; s++) if (*s == from) *s = to;
}

const char *strncasestr(const char *s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++))
	{
		len = strlen(find);
		do
		{
			do
			{
				if (!slen) return NULL;
				slen--;
				sc = *s++;
			} while (toupper((unsigned char)c) != toupper((unsigned char)sc));
			if (len > slen)	return NULL;
		} while (strncasecmp(s, find, len));
		s--;
	}
	return s;
}

static inline bool is_letter(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static inline bool is_digit(char c)
{
	return c >= '0' && c <= '9';
}
bool is_identifier(const char *p)
{
	if (*p != '_' && !is_letter(*p))
		return false;
	for (++p; *p; p++)
		if (!is_letter(*p) && !is_digit(*p) && *p != '_')
			return false;
	return true;
}

bool load_file(const char *filename, off_t offset, void *buffer, size_t *buffer_size)
{
	FILE *F;

	F = fopen(filename, "rb");
	if (!F) return false;

	if (offset)
	{
		if (fseek(F, offset, SEEK_SET))
		{
			fclose(F);
			return false;
		}
	}

	if (!fread_safe(buffer, 1, *buffer_size, F, buffer_size))
	{
		fclose(F);
		return false;
	}

	fclose(F);
	return true;
}
bool save_file(const char *filename, const void *buffer, size_t buffer_size)
{
	FILE *F;

	F = fopen(filename, "wb");
	if (!F) return false;
	size_t wr = fwrite(buffer, 1, buffer_size, F);
	if (ferror(F))
	{
		fclose(F);
		return false;
	}
	fclose(F);
	if (wr != buffer_size)
	{
		errno = EIO;
		return false;
	}
	return true;
}
bool append_to_list_file(const char *filename, const char *s)
{
	FILE *F = fopen(filename, "at");
	if (!F) return false;
	bool bOK = fprintf(F, "%s\n", s) > 0;
	fclose(F);
	return bOK;
}

void expand_bits(void *target, const void *source, unsigned int source_bitlen, unsigned int target_bytelen)
{
	unsigned int target_bitlen = target_bytelen << 3;
	unsigned int bitlen = target_bitlen < source_bitlen ? target_bitlen : source_bitlen;
	unsigned int bytelen = bitlen >> 3;

	if ((target_bytelen - bytelen) >= 1) memset((uint8_t*)target + bytelen, 0, target_bytelen - bytelen);
	memcpy(target, source, bytelen);
	if ((bitlen &= 7)) ((uint8_t*)target)[bytelen] = ((uint8_t*)source)[bytelen] & (~((1 << (8 - bitlen)) - 1));
}

// "       [fd00::1]" => "fd00::1"
// "[fd00::1]:8000" => "fd00::1"
// "127.0.0.1" => "127.0.0.1"
// " 127.0.0.1:8000" => "127.0.0.1"
// " vk.com:8000" => "vk.com"
// return value:  true - host is ip addr
bool strip_host_to_ip(char *host)
{
	size_t l;
	char *h, *p;
	uint8_t addr[16];

	for (h = host; *h == ' ' || *h == '\t'; h++);
	l = strlen(h);
	if (l >= 2)
	{
		if (*h == '[')
		{
			// ipv6 ?
			for (p = ++h; *p && *p != ']'; p++);
			if (*p == ']')
			{
				l = p - h;
				memmove(host, h, l);
				host[l] = 0;
				return inet_pton(AF_INET6, host, addr) > 0;
			}
		}
		else
		{
			if (inet_pton(AF_INET6, h, addr) > 0)
			{
				// ipv6 ?
				if (host != h)
				{
					l = strlen(h);
					memmove(host, h, l);
					host[l] = 0;
				}
				return true;
			}
			else
			{
				// ipv4 ?
				for (p = h; *p && *p != ':'; p++);
				l = p - h;
				if (host != h) memmove(host, h, l);
				host[l] = 0;
				return inet_pton(AF_INET, host, addr) > 0;
			}
		}
	}
	return false;
}

void ntopa46(const struct in_addr *ip, const struct in6_addr *ip6, char *str, size_t len)
{
	if (!len) return;
	*str = 0;
	if (ip)	inet_ntop(AF_INET, ip, str, len);
	else if (ip6) inet_ntop(AF_INET6, ip6, str, len);
	else snprintf(str, len, "UNKNOWN_FAMILY");
}
void ntop46(const struct sockaddr *sa, char *str, size_t len)
{
	ntopa46(sa->sa_family == AF_INET ? &((struct sockaddr_in*)sa)->sin_addr : NULL,
		sa->sa_family == AF_INET6 ? &((struct sockaddr_in6*)sa)->sin6_addr : NULL,
		str, len);
}
void ntop46_port(const struct sockaddr *sa, char *str, size_t len)
{
	char ip[INET6_ADDRSTRLEN];
	ntop46(sa, ip, sizeof(ip));
	switch (sa->sa_family)
	{
	case AF_INET:
		snprintf(str, len, "%s:%u", ip, ntohs(((struct sockaddr_in*)sa)->sin_port));
		break;
	case AF_INET6:
		snprintf(str, len, "[%s]:%u", ip, ntohs(((struct sockaddr_in6*)sa)->sin6_port));
		break;
	default:
		snprintf(str, len, "%s", ip);
	}
}
void print_sockaddr(const struct sockaddr *sa)
{
	char ip_port[48];

	ntop46_port(sa, ip_port, sizeof(ip_port));
	printf("%s", ip_port);
}

uint16_t saport(const struct sockaddr *sa)
{
	return ntohs(sa->sa_family == AF_INET ? ((struct sockaddr_in*)sa)->sin_port :
		sa->sa_family == AF_INET6 ? ((struct sockaddr_in6*)sa)->sin6_port : 0);
}

bool sa_has_addr(const struct sockaddr *sa)
{
	switch (sa->sa_family)
	{
	case AF_INET:
		return ((struct sockaddr_in*)sa)->sin_addr.s_addr != INADDR_ANY;
	case AF_INET6:
		return memcmp(((struct sockaddr_in6*)sa)->sin6_addr.s6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
	default:
		return false;
	}
}


bool seq_within(uint32_t s, uint32_t s1, uint32_t s2)
{
	return (s2 >= s1 && s >= s1 && s <= s2) || (s2 < s1 && (s <= s2 || s >= s1));
}

bool ipv6_addr_is_zero(const struct in6_addr *a)
{
	return !memcmp(a, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
}


uint16_t pntoh16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
void phton16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = v & 0xFF;
}
uint32_t pntoh24(const uint8_t *p)
{
	return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}
void phton24(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 16);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)v;
}
uint32_t pntoh32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
void phton32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}
uint64_t pntoh48(const uint8_t *p)
{
	return ((uint64_t)p[0] << 40) | ((uint64_t)p[1] << 32) | ((uint64_t)p[2] << 24) | ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 8) | p[5];
}
void phton48(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)(v >> 40);
	p[1] = (uint8_t)(v >> 32);
	p[2] = (uint8_t)(v >> 24);
	p[3] = (uint8_t)(v >> 16);
	p[4] = (uint8_t)(v >> 8);
	p[5] = (uint8_t)v;
}
uint64_t pntoh64(const uint8_t *p)
{
	return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] << 8) | p[7];
}
void phton64(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)(v >> 56);
	p[1] = (uint8_t)(v >> 48);
	p[2] = (uint8_t)(v >> 40);
	p[3] = (uint8_t)(v >> 32);
	p[4] = (uint8_t)(v >> 24);
	p[5] = (uint8_t)(v >> 16);
	p[6] = (uint8_t)(v >> 8);
	p[7] = (uint8_t)v;
}

uint16_t bswap16(uint16_t u)
{
	// __builtin_bswap16 is absent in ancient lexra gcc 4.6
	return (u >> 8) | ((u & 0xFF) << 8);
}
uint32_t bswap24(uint32_t u)
{
	return (u >> 16) & 0xFF | u & 0xFF00 | (u << 16) & 0xFF0000;
}
uint64_t bswap48(uint64_t u)
{
	return ((u & 0xFF0000000000) >> 40) | ((u & 0xFF00000000) >> 24) | ((u & 0xFF000000) >> 8) | ((u & 0xFF0000) << 8) | ((u & 0xFF00) << 24) | ((u & 0xFF) << 40);
}


#define INVALID_HEX_DIGIT ((uint8_t)-1)
static inline uint8_t parse_hex_digit(char c)
{
	return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 0xA : (c >= 'A' && c <= 'F') ? c - 'A' + 0xA : INVALID_HEX_DIGIT;
}
static inline bool parse_hex_byte(const char *s, uint8_t *pbyte)
{
	uint8_t u, l;
	u = parse_hex_digit(s[0]);
	l = parse_hex_digit(s[1]);
	if (u == INVALID_HEX_DIGIT || l == INVALID_HEX_DIGIT)
	{
		*pbyte = 0;
		return false;
	}
	else
	{
		*pbyte = (u << 4) | l;
		return true;
	}
}
bool parse_hex_str(const char *s, uint8_t *pbuf, size_t *size)
{
	uint8_t *pe = pbuf + *size;
	*size = 0;
	while (pbuf < pe && *s)
	{
		if (!parse_hex_byte(s, pbuf))
			return false;
		pbuf++; s += 2; (*size)++;
	}
	return true;
}
char hex_digit(uint8_t v)
{
	return v <= 9 ? '0' + v : (v <= 0xF) ? v + 'A' - 0xA : '?';
}

int fprint_localtime(FILE *F)
{
	struct tm t;
	time_t now;

	time(&now);
	localtime_r(&now, &t);
	return fprintf(F, "%02d.%02d.%04d %02d:%02d:%02d", t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, t.tm_hour, t.tm_min, t.tm_sec);
}

bool file_size(const char *filename, off_t *size)
{
	struct stat st;
	if (stat(filename, &st) == -1) return false;
	*size = st.st_size;
	return true;
}
time_t file_mod_time(const char *filename)
{
	struct stat st;
	return stat(filename, &st) == -1 ? 0 : st.st_mtime;
}
bool file_mod_signature(const char *filename, file_mod_sig *ms)
{
	struct stat st;
	if (stat(filename, &st) == -1)
	{
		FILE_MOD_RESET(ms);
		return false;
	}
	ms->mod_time = st.st_mtime;
	ms->size = st.st_size;
	return true;
}

bool file_open_test(const char *filename, int flags)
{
	int fd = open(filename, flags);
	if (fd >= 0)
	{
		close(fd);
		return true;
	}
	return false;
}


void fill_random_bytes(uint8_t *p, size_t sz)
{
	size_t k;
	if (sz)
	{
		// alignment
		if ((size_t)p & 1) { *p = (uint8_t)random(); sz--; p++; }
		// random has only 31 bits of entropy. not 32 bits
		for (k = 0; (k + 1) < sz; k += 2) *(uint16_t*)(p + k) = (uint16_t)random();
		if (sz & 1) p[sz - 1] = (uint8_t)random();
	}
}
void fill_random_az(uint8_t *p, size_t sz)
{
	size_t k;
	for (k = 0; k < sz; k++) p[k] = 'a' + (random() % ('z' - 'a' + 1));
}
void fill_random_az09(uint8_t *p, size_t sz)
{
	size_t k;
	uint8_t rnd;
	for (k = 0; k < sz; k++)
	{
		rnd = random() % (10 + 'z' - 'a' + 1);
		p[k] = rnd < 10 ? rnd + '0' : 'a' + rnd - 10;
	}
}
#if defined(__FreeBSD__) && __FreeBSD_version <= 1200000
#include <sys/sysctl.h>
int getentropy(void *buf, size_t len)
{
	int mib[2];
	size_t size = len;

	// Check for reasonable length (getentropy limits to 256)
	if (len > 256) {
		errno = EIO;
		return -1;
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_ARND;

	if (sysctl(mib, 2, buf, &size, NULL, 0) == -1) {
		return -1;
	}

	return (size == len) ? 0 : -1;
}
#endif


ssize_t read_intr(int fd, void *buf, size_t count)
{
	ssize_t rd;
	while ((rd = read(fd, buf, count)) < 0 && errno == EINTR);
	return rd;
}

bool fread_safe(void *ptr, size_t size, size_t nmemb, FILE *F, size_t *rd)
{
	size_t result, to_read, total_read = 0;
	while (total_read < nmemb)
	{
		to_read = nmemb - total_read;
		errno = 0;
		total_read += (result = fread((uint8_t*)ptr + (total_read * size), size, to_read, F));
		if (result < to_read)
		{
			if (ferror(F))
			{
				if (errno == EINTR)
				{
					clearerr(F);
					continue;
				}
				*rd = total_read;
				return false;
			}
			break;
		}
	}
	*rd = total_read;
	return true;
}
char* fgets_safe(char *s, int size, FILE *stream)
{
	char *result;

	while (true)
	{
		errno = 0;
		if ((result = fgets(s, size, stream))) return result;
		if (ferror(stream))
		{
			if (errno == EINTR)
			{
				clearerr(stream);
				continue;
			}
			return NULL;
		}
		if (feof(stream)) return NULL;
	}
}

bool fill_crypto_random_bytes(uint8_t *p, size_t sz)
{
	ssize_t rd;
	int fd;

#if defined(__linux__) || defined(__CYGWIN__)
	for (; sz && (rd = getrandom(p, sz, GRND_NONBLOCK)) > 0; p += rd, sz -= rd);
	if (sz)
#elif defined(BSD)
	while (sz)
	{
		rd = sz < 256 ? sz : 256; // BSD limitation
		if (getentropy(p, rd)) break;
		p += rd; sz -= rd;
	}
	if (sz)
#endif
	{
		if ((fd = open("/dev/random", O_NONBLOCK)) >= 0)
		{
			do
			{
				if ((rd = read_intr(fd, p, sz)) > 0)
				{
					p += rd; sz -= rd;
				}
			} while (sz && rd > 0);
			close(fd);
		}
		if (sz && (fd = open("/dev/urandom", 0)) >= 0)
		{
			do
			{
				if ((rd = read_intr(fd, p, sz)) > 0)
				{
					p += rd; sz -= rd;
				}
			} while (sz && rd > 0);
			close(fd);
		}
	}
	return !sz;
}

#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize("no-strict-aliasing")))
#endif
void bxor(const uint8_t *x1, const uint8_t *x2, uint8_t *result, size_t sz)
{
	for (; sz >= 8; x1 += 8, x2 += 8, result += 8, sz -= 8)
		*(uint64_t*)result = *(uint64_t*)x1 ^ *(uint64_t*)x2;
	for (; sz; x1++, x2++, result++, sz--)
		*result = *x1 ^ *x2;
}
#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize("no-strict-aliasing")))
#endif
void bor(const uint8_t *x1, const uint8_t *x2, uint8_t *result, size_t sz)
{
	for (; sz >= 8; x1 += 8, x2 += 8, result += 8, sz -= 8)
		*(uint64_t*)result = *(uint64_t*)x1 | *(uint64_t*)x2;
	for (; sz; x1++, x2++, result++, sz--)
		*result = *x1 | *x2;
}
#if defined(__GNUC__) && !defined(__llvm__)
__attribute__((optimize("no-strict-aliasing")))
#endif
void band(const uint8_t *x1, const uint8_t *x2, uint8_t *result, size_t sz)
{
	for (; sz >= 8; x1 += 8, x2 += 8, result += 8, sz -= 8)
		*(uint64_t*)result = *(uint64_t*)x1 & *(uint64_t*)x2;
	for (; sz; x1++, x2++, result++, sz--)
		*result = *x1 & *x2;
}



void set_console_io_buffering(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);
}
void close_std(void)
{
	// free memory allocated by setvbuf
	fclose(stdout);
	fclose(stderr);
}
void close_std_and_exit(int code)
{
	close_std();
	exit(code);
}

bool set_env_exedir(const char *argv0)
{
	char *s, *d;
	bool bOK = false;
	if ((s = strdup(argv0)))
	{
		if ((d = dirname(s)))
		{
			char d_abs[PATH_MAX];
			if (realpath(d, d_abs))
				d=d_abs;
			bOK = !setenv("EXEDIR", d, 1);
		}
		free(s);
	}
	return bOK;
}

// works for existing and new files
bool realpath_any(const char *file, char *pabs)
{
	bool b = true;
	char *s1=NULL, *s2=NULL;
	int res;
	size_t l;

#ifdef __CYGWIN__
	l = cygwin_conv_path(CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, file, NULL, 0);
	char *rp_file = (char*)malloc(l);
	if (cygwin_conv_path(CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, file, rp_file, l))
		goto err;
#else
#define rp_file file
#endif

	if (!realpath(rp_file,pabs))
	{
		char pa[PATH_MAX], *dir, *base;
		if (!(s1 = strdup(rp_file))) goto err;
		dir = dirname(s1);
		if (!realpath(dir,pa))
			goto err;
		if (!(s2 = strdup(rp_file))) goto err;
		base = basename(s2);
		l = strlen(pa);
		if (l && pa[l-1]=='/')
			res=snprintf(pabs,PATH_MAX,"%s%s",pa, base);
		else
			res=snprintf(pabs,PATH_MAX,"%s/%s",pa,base);
		b = res>0 && res<PATH_MAX;
	}
ex:
#ifdef __CYGWIN__
	free(rp_file);
#else
#undef rp_file
#endif
	free(s1);
	free(s2);
	return b;
err:
	b = false;
	goto ex;
}

bool parse_int16(const char *p, int16_t *v)
{
	if (*p == '+' || *p == '-' || *p >= '0' && *p <= '9')
	{
		int i = atoi(p);
		*v = (int16_t)i;
		return *v == i; // check overflow
	}
	return false;
}


time_t boottime(void)
{
	struct timespec ts;
	return clock_gettime(CLOCK_BOOT_OR_UPTIME, &ts) ? 0 : ts.tv_sec;
}
uint64_t boottime_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_BOOT_OR_UPTIME, &ts))
		return 0;
	else
		return ts.tv_sec*1000ULL + ts.tv_nsec/1000000;
}


#ifdef __CYGWIN__
uint32_t mask_from_bitcount(uint32_t zct)
{
	return zct < 32 ? ~((1u << zct) - 1) : 0;
}
static void mask_from_bitcount6_make(uint32_t zct, struct in6_addr *a)
{
	if (zct >= 128)
		memset(a->s6_addr, 0x00, 16);
	else
	{
		int32_t n = (127 - zct) >> 3;
		memset(a->s6_addr, 0xFF, n);
		memset(a->s6_addr + n, 0x00, 16 - n);
		a->s6_addr[n] = ~((1u << (zct & 7)) - 1);
	}
}
static struct in6_addr ip6_mask[129];
void mask_from_bitcount6_prepare(void)
{
	for (int zct = 0; zct <= 128; zct++) mask_from_bitcount6_make(zct, ip6_mask + zct);
}
const struct in6_addr *mask_from_bitcount6(uint32_t zct)
{
	return ip6_mask + zct;
}
#endif
