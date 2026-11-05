#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>

#define UNARY_PLUS(v) (v>0 ? "+" : "")
//#define	MIN(v1,v2) ((v1)<(v2) ? (v1) : (v2))
//#define	MAX(v1,v2) ((v1)<(v2) ? (v2) : (v1))


// this saves memory. sockaddr_storage is larger than required. it can be 128 bytes. sockaddr_in6 is 28 bytes.
typedef union
{
	struct sockaddr_in sa4;		// size 16
	struct sockaddr_in6 sa6;	// size 28
	char _align[32];		// force 16-byte alignment for ip6_and int128 ops
} sockaddr_in46;

int unique_size_t(size_t *pu, int ct);
int unique_ssize_t(ssize_t *pu, int ct);
void qsort_size_t(size_t *array, int ct);
void qsort_ssize_t(ssize_t *array, int ct);

int str_index(const char **strs, int count, const char *str);
void rtrim(char *s);
void replace_char(char *s, char from, char to);
const char *strncasestr(const char *s,const char *find, size_t slen);
// [a-zA-z][a-zA-Z0-9]*
bool is_identifier(const char *p);

ssize_t read_intr(int fd, void *buf, size_t count);
bool fread_safe(void *ptr, size_t size, size_t nmemb, FILE *F, size_t *rd);
char* fgets_safe(char *s, int size, FILE *stream);

bool load_file(const char *filename, off_t offset, void *buffer, size_t *buffer_size);
bool save_file(const char *filename, const void *buffer, size_t buffer_size);
bool append_to_list_file(const char *filename, const char *s);

void expand_bits(void *target, const void *source, unsigned int source_bitlen, unsigned int target_bytelen);

bool strip_host_to_ip(char *host);

void print_sockaddr(const struct sockaddr *sa);
void ntopa46(const struct in_addr *ip, const struct in6_addr *ip6,char *str, size_t len);
void ntop46(const struct sockaddr *sa, char *str, size_t len);
void ntop46_port(const struct sockaddr *sa, char *str, size_t len);

uint16_t saport(const struct sockaddr *sa);
bool sa_has_addr(const struct sockaddr *sa);

bool seq_within(uint32_t s, uint32_t s1, uint32_t s2);

bool ipv6_addr_is_zero(const struct in6_addr *a);

uint16_t pntoh16(const uint8_t *p);
void phton16(uint8_t *p, uint16_t v);
uint32_t pntoh24(const uint8_t *p);
void phton24(uint8_t *p, uint32_t v);
uint32_t pntoh32(const uint8_t *p);
void phton32(uint8_t *p, uint32_t v);
uint64_t pntoh48(const uint8_t *p);
void phton48(uint8_t *p, uint64_t v);
uint64_t pntoh64(const uint8_t *p);
void phton64(uint8_t *p, uint64_t v);

uint16_t bswap16(uint16_t u);
uint32_t bswap24(uint32_t u);
uint64_t bswap48(uint64_t u);

bool parse_hex_str(const char *s, uint8_t *pbuf, size_t *size);
char hex_digit(uint8_t v);

int fprint_localtime(FILE *F);

typedef struct
{
	struct timespec mod_time;
	off_t size;
} file_mod_sig;
#define FILE_MOD_COMPARE(ms1,ms2) (((ms1)->mod_time.tv_sec==(ms2)->mod_time.tv_sec) && ((ms1)->mod_time.tv_nsec==(ms2)->mod_time.tv_nsec) && ((ms1)->size==(ms2)->size))
#define FILE_MOD_RESET(ms) memset(ms,0,sizeof(file_mod_sig))
bool file_mod_signature(const char *filename, file_mod_sig *ms);
bool file_size(const char *filename, off_t *size);
bool file_open_test(const char *filename, int flags);

#if defined(__FreeBSD__) && __FreeBSD_version <= 1200000
int getentropy(void *buf, size_t len);
#endif

void fill_random_bytes(uint8_t *p,size_t sz);
void fill_random_az(uint8_t *p,size_t sz);
void fill_random_az09(uint8_t *p,size_t sz);
bool fill_crypto_random_bytes(uint8_t *p,size_t sz);

void bxor(const uint8_t *x1, const uint8_t *x2, uint8_t *result, size_t sz);
void band(const uint8_t *x1, const uint8_t *x2, uint8_t *result, size_t sz);
void bor(const uint8_t *x1, const uint8_t *x2, uint8_t *result, size_t sz);

void set_console_io_buffering(void);
void close_std(void);
void close_std_and_exit(int code);
bool set_env_exedir(const char *argv0);
bool realpath_any(const char *file, char *pabs);

bool parse_int16(const char *p, int16_t *v);

#ifdef CLOCK_BOOTTIME
#define CLOCK_BOOT_OR_UPTIME CLOCK_BOOTTIME
#elif defined(CLOCK_UPTIME)
#define CLOCK_BOOT_OR_UPTIME CLOCK_UPTIME
#else
#define CLOCK_BOOT_OR_UPTIME CLOCK_MONOTONIC
#endif

time_t boottime(void);
uint64_t boottime_ms(void);

#ifdef __CYGWIN__
uint32_t mask_from_bitcount(uint32_t zct);
void mask_from_bitcount6_prepare(void);
const struct in6_addr *mask_from_bitcount6(uint32_t zct);
#endif
