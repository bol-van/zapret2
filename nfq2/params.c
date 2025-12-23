#include "params.h"

#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

#include "pools.h"
#include "lua.h"

#ifdef BSD
const char *progname = "dvtws2";
#elif defined(__CYGWIN__)
const char *progname = "winws2";
#elif defined(__linux__)
const char *progname = "nfqws2";
#else
#error UNKNOWN_SYSTEM_TIME
#endif

const char *fake_http_request_default = "GET / HTTP/1.1\r\nHost: www.iana.org\r\n"
"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
"Accept-Encoding: gzip, deflate, br\r\n\r\n";

// SNI - www.microsoft.com
const uint8_t fake_tls_clienthello_default[680] = {
  0x16, 0x03, 0x01, 0x02, 0xa3, 0x01, 0x00, 0x02, 0x9f, 0x03, 0x03, 0x41,
  0x88, 0x82, 0x2d, 0x4f, 0xfd, 0x81, 0x48, 0x9e, 0xe7, 0x90, 0x65, 0x1f,
  0xba, 0x05, 0x7b, 0xff, 0xa7, 0x5a, 0xf9, 0x5b, 0x8a, 0x8f, 0x45, 0x8b,
  0x41, 0xf0, 0x3d, 0x1b, 0xdd, 0xe3, 0xf8, 0x20, 0x9b, 0x23, 0xa5, 0xd2,
  0x21, 0x1e, 0x9f, 0xe7, 0x85, 0x6c, 0xfc, 0x61, 0x80, 0x3a, 0x3f, 0xba,
  0xb9, 0x60, 0xba, 0xb3, 0x0e, 0x98, 0x27, 0x6c, 0xf7, 0x38, 0x28, 0x65,
  0x80, 0x5d, 0x40, 0x38, 0x00, 0x22, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02,
  0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30,
  0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d,
  0x00, 0x2f, 0x00, 0x35, 0x01, 0x00, 0x02, 0x34, 0x00, 0x00, 0x00, 0x16,
  0x00, 0x14, 0x00, 0x00, 0x11, 0x77, 0x77, 0x77, 0x2e, 0x6d, 0x69, 0x63,
  0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17,
  0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0e, 0x00,
  0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01,
  0x01, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
  0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74,
  0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x05, 0x03,
  0x06, 0x03, 0x02, 0x03, 0x00, 0x12, 0x00, 0x00, 0x00, 0x33, 0x00, 0x6b,
  0x00, 0x69, 0x00, 0x1d, 0x00, 0x20, 0x69, 0x15, 0x16, 0x29, 0x6d, 0xad,
  0xd5, 0x68, 0x88, 0x27, 0x2f, 0xde, 0xaf, 0xac, 0x3c, 0x4c, 0xa4, 0xe4,
  0xd8, 0xc8, 0xfb, 0x41, 0x87, 0xf4, 0x76, 0x4e, 0x0e, 0xfa, 0x64, 0xc4,
  0xe9, 0x29, 0x00, 0x17, 0x00, 0x41, 0x04, 0xfe, 0x62, 0xb9, 0x08, 0xc8,
  0xc3, 0x2a, 0xb9, 0x87, 0x37, 0x84, 0x42, 0x6b, 0x5c, 0xcd, 0xc9, 0xca,
  0x62, 0x38, 0xd3, 0xd9, 0x99, 0x8a, 0xc4, 0x2d, 0xc6, 0xd0, 0xa3, 0x60,
  0xb2, 0x12, 0x54, 0x41, 0x8e, 0x52, 0x5e, 0xe3, 0xab, 0xf9, 0xc2, 0x07,
  0x81, 0xdc, 0xf8, 0xf2, 0x6a, 0x91, 0x40, 0x2f, 0xcb, 0xa4, 0xff, 0x6f,
  0x24, 0xc7, 0x4d, 0x77, 0x77, 0x2d, 0x6f, 0xe0, 0x77, 0xaa, 0x92, 0x00,
  0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x0d, 0x00, 0x18,
  0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05,
  0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01,
  0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01,
  0x00, 0x1b, 0x00, 0x07, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0xfe,
  0x0d, 0x01, 0x19, 0x00, 0x00, 0x01, 0x00, 0x03, 0x21, 0x00, 0x20, 0x62,
  0xe8, 0x83, 0xd8, 0x97, 0x05, 0x8a, 0xbe, 0xa1, 0xf2, 0x63, 0x4e, 0xce,
  0x93, 0x84, 0x8e, 0xcf, 0xe7, 0xdd, 0xb2, 0xe4, 0x87, 0x06, 0xac, 0x11,
  0x19, 0xbe, 0x0e, 0x71, 0x87, 0xf1, 0xa6, 0x00, 0xef, 0xd8, 0x6b, 0x27,
  0x5e, 0xc0, 0xa7, 0x5d, 0x42, 0x4e, 0x8c, 0xdc, 0xf3, 0x9f, 0x1c, 0x51,
  0x62, 0xef, 0xff, 0x5b, 0xed, 0xc8, 0xfd, 0xee, 0x6f, 0xbb, 0x88, 0x9b,
  0xb1, 0x30, 0x9c, 0x66, 0x42, 0xab, 0x0f, 0x66, 0x89, 0x18, 0x8b, 0x11,
  0xc1, 0x6d, 0xe7, 0x2a, 0xeb, 0x96, 0x3b, 0x7f, 0x52, 0x78, 0xdb, 0xf8,
  0x6d, 0x04, 0xf7, 0x95, 0x1a, 0xa8, 0xf0, 0x64, 0x52, 0x07, 0x39, 0xf0,
  0xa8, 0x1d, 0x0d, 0x16, 0x36, 0xb7, 0x18, 0x0e, 0xc8, 0x44, 0x27, 0xfe,
  0xf3, 0x31, 0xf0, 0xde, 0x8c, 0x74, 0xf5, 0xa1, 0xd8, 0x8f, 0x6f, 0x45,
  0x97, 0x69, 0x79, 0x5e, 0x2e, 0xd4, 0xb0, 0x2c, 0x0c, 0x1a, 0x6f, 0xcc,
  0xce, 0x90, 0xc7, 0xdd, 0xc6, 0x60, 0x95, 0xf3, 0xc2, 0x19, 0xde, 0x50,
  0x80, 0xbf, 0xde, 0xf2, 0x25, 0x63, 0x15, 0x26, 0x63, 0x09, 0x1f, 0xc5,
  0xdf, 0x32, 0xf5, 0xea, 0x9c, 0xd2, 0xff, 0x99, 0x4e, 0x67, 0xa2, 0xe5,
  0x1a, 0x94, 0x85, 0xe3, 0xdf, 0x36, 0xa5, 0x83, 0x4b, 0x0a, 0x1c, 0xaf,
  0xd7, 0x48, 0xc9, 0x4b, 0x8a, 0x27, 0xdd, 0x58, 0x7f, 0x95, 0xf2, 0x6b,
  0xde, 0x2b, 0x12, 0xd3, 0xec, 0x4d, 0x69, 0x37, 0x9c, 0x13, 0x9b, 0x16,
  0xb0, 0x45, 0x52, 0x38, 0x77, 0x69, 0xef, 0xaa, 0x65, 0x19, 0xbc, 0xc2,
  0x93, 0x4d, 0xb0, 0x1b, 0x7f, 0x5b, 0x41, 0xff, 0xaf, 0xba, 0x50, 0x51,
  0xc3, 0xf1, 0x27, 0x09, 0x25, 0xf5, 0x60, 0x90, 0x09, 0xb1, 0xe5, 0xc0,
  0xc7, 0x42, 0x78, 0x54, 0x3b, 0x23, 0x19, 0x7d, 0x8e, 0x72, 0x13, 0xb4,
  0xd3, 0xcd, 0x63, 0xb6, 0xc4, 0x4a, 0x28, 0x3d, 0x45, 0x3e, 0x8b, 0xdb,
  0x84, 0x4f, 0x78, 0x64, 0x30, 0x69, 0xe2, 0x1b
};

const char * tld[6] = { "com","org","net","edu","gov","biz" };

int DLOG_FILE_VA(FILE *F, const char *format, va_list args)
{
	return vfprintf(F, format, args);
}
int DLOG_CON_VA(const char *format, int syslog_priority, va_list args)
{
	return DLOG_FILE_VA(syslog_priority==LOG_ERR ? stderr : stdout, format, args);
}
int DLOG_FILENAME_VA(const char *filename, const char *format, va_list args)
{
	int r;
	FILE *F = fopen(filename,"at");
	if (F)
	{
		r = DLOG_FILE_VA(F, format, args);
		fclose(F);
	}
	else
		r=-1;
	return r;
}

typedef void (*f_log_function)(int priority, const char *line);

static char log_buf[4096];
static size_t log_buf_sz=0;
static void syslog_log_function(int priority, const char *line)
{
	syslog(priority,"%s",log_buf);
}

static int DLOG_FILENAME(const char *filename, const char *format, ...)
{
	int r;
	va_list args;
	va_start(args, format);
	r = DLOG_FILENAME_VA(filename, format, args);
	va_end(args);
	return r;
}
static void file_log_function(int priority, const char *line)
{
	DLOG_FILENAME(params.debug_logfile,"%s",log_buf);
}

#ifdef __ANDROID__
static enum android_LogPriority syslog_priority_to_android(int priority)
{
	enum android_LogPriority ap;
	switch(priority)
	{
		case LOG_INFO:
		case LOG_NOTICE: ap=ANDROID_LOG_INFO; break;
		case LOG_ERR: ap=ANDROID_LOG_ERROR; break;
		case LOG_WARNING: ap=ANDROID_LOG_WARN; break;
		case LOG_EMERG:
		case LOG_ALERT:
		case LOG_CRIT: ap=ANDROID_LOG_FATAL; break;
		case LOG_DEBUG: ap=ANDROID_LOG_DEBUG; break;
		default: ap=ANDROID_LOG_UNKNOWN;
	}
	return ap;
}
static void android_log_function(int priority, const char *line)
{
	__android_log_print(syslog_priority_to_android(priority), progname, "%s", line);
}
#endif
static void log_buffered(f_log_function log_function, int syslog_priority, const char *format, va_list args)
{
	if (vsnprintf(log_buf+log_buf_sz,sizeof(log_buf)-log_buf_sz-1,format,args)>0)
	{
		log_buf_sz=strlen(log_buf);
		// log when buffer is full or buffer ends with \n
		if (log_buf_sz==(sizeof(log_buf)-2))
		{
			log_buf[log_buf_sz++] = '\n';
			log_buf[log_buf_sz] = 0;
			log_function(syslog_priority,log_buf);
			log_buf_sz = 0;
		}
		else if (log_buf_sz && log_buf[log_buf_sz-1]=='\n')
		{
			log_function(syslog_priority,log_buf);
			log_buf_sz = 0;
		}
	}
}

static int DLOG_VA(const char *format, int syslog_priority, bool condup, va_list args)
{
	int r=0;
	va_list args2;

	if (condup && !(params.debug && params.debug_target==LOG_TARGET_CONSOLE))
	{
		va_copy(args2,args);
		DLOG_CON_VA(format,syslog_priority,args2);
		va_end(args2);
	}
	if (params.debug)
	{
		switch(params.debug_target)
		{
			case LOG_TARGET_CONSOLE:
				r = DLOG_CON_VA(format,syslog_priority,args);
				break;
			case LOG_TARGET_FILE:
				log_buffered(file_log_function,syslog_priority,format,args);
				r = 1;
				break;
			case LOG_TARGET_SYSLOG:
				// skip newlines
				log_buffered(syslog_log_function,syslog_priority,format,args);
				r = 1;
				break;
#ifdef __ANDROID__
			case LOG_TARGET_ANDROID:
				// skip newlines
				log_buffered(android_log_function,syslog_priority,format,args);
				r = 1;
				break;
#endif
			default:
				break;
		}
	}
	return r;
}

int DLOG(const char *format, ...)
{
	int r;
	va_list args;
	va_start(args, format);
	r = DLOG_VA(format, LOG_DEBUG, false, args);
	va_end(args);
	return r;
}
int DLOG_CONDUP(const char *format, ...)
{
	int r;
	va_list args;
	va_start(args, format);
	r = DLOG_VA(format, LOG_DEBUG, true, args);
	va_end(args);
	return r;
}
int DLOG_ERR(const char *format, ...)
{
	int r;
	va_list args;
	va_start(args, format);
	r = DLOG_VA(format, LOG_ERR, true, args);
	va_end(args);
	return r;
}
int DLOG_PERROR(const char *s)
{
	return DLOG_ERR("%s: %s\n", s, strerror(errno));
}


int LOG_APPEND(const char *filename, const char *format, va_list args)
{
	int r;
	FILE *F = fopen(filename,"at");
	if (F)
	{
		fprint_localtime(F);
		fprintf(F, " : ");
		r = vfprintf(F, format, args);
		fprintf(F, "\n");
		fclose(F);
	}
	else
		r=-1;
	return r;
}

int HOSTLIST_DEBUGLOG_APPEND(const char *format, ...)
{
	if (*params.hostlist_auto_debuglog)
	{
		int r;
		va_list args;

		va_start(args, format);
		r = LOG_APPEND(params.hostlist_auto_debuglog, format, args);
		va_end(args);
		return r;
	}
	else
		return 0;
}

void hexdump_limited_dlog(const uint8_t *data, size_t size, size_t limit)
{
	size_t k;
	bool bcut = false;
	if (size > limit)
	{
		size = limit;
		bcut = true;
	}
	if (!size) return;

	char *p, *buf = malloc(size*4 + 16);
	if (buf)
	{
		p=buf;
		for (k = 0; k < size; k++)
		{
			*p++ = hex_digit(data[k] >> 4);
			*p++ = hex_digit(data[k] & 0xF);
			*p++ = ' ';
		}
		if (bcut)
		{
			*p++='.';
			*p++='.';
			*p++='.';
			*p++=' ';
		}
		*p++=':';
		*p++=' ';
		for (k = 0; k < size; k++)
			*p++ = data[k] >= 0x20 && data[k] <= 0x7F ? (char)data[k] : '.';
		if (bcut)
		{
			*p++=' ';
			*p++='.';
			*p++='.';
			*p++='.';
		}
		*p = 0;
		DLOG("%s", buf);
		free(buf);
	}
}

void dp_init_dynamic(struct desync_profile *dp)
{
	LIST_INIT(&dp->hl_collection);
	LIST_INIT(&dp->hl_collection_exclude);
	LIST_INIT(&dp->ips_collection);
	LIST_INIT(&dp->ips_collection_exclude);
	LIST_INIT(&dp->pf_tcp);
	LIST_INIT(&dp->pf_udp);
	LIST_INIT(&dp->lua_desync);
#ifdef HAS_FILTER_SSID
	LIST_INIT(&dp->filter_ssid);
#endif
}
void dp_init(struct desync_profile *dp)
{
	dp_init_dynamic(dp);

	dp->hostlist_auto_fail_threshold = HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT;
	dp->hostlist_auto_fail_time = HOSTLIST_AUTO_FAIL_TIME_DEFAULT;
	dp->hostlist_auto_retrans_threshold = HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT;
	dp->hostlist_auto_retrans_maxseq = HOSTLIST_AUTO_RETRANS_MAXSEQ;
	dp->hostlist_auto_retrans_reset = true;
	dp->hostlist_auto_incoming_maxseq = HOSTLIST_AUTO_INCOMING_MAXSEQ;
	dp->hostlist_auto_udp_out = HOSTLIST_AUTO_UDP_OUT;
	dp->hostlist_auto_udp_in = HOSTLIST_AUTO_UDP_IN;
	dp->filter_ipv4 = dp->filter_ipv6 = true;
}
static void dp_clear_dynamic(struct desync_profile *dp)
{
	free(dp->name);
	free(dp->name_tpl);
	free(dp->cookie);

	hostlist_collection_destroy(&dp->hl_collection);
	hostlist_collection_destroy(&dp->hl_collection_exclude);
	ipset_collection_destroy(&dp->ips_collection);
	ipset_collection_destroy(&dp->ips_collection_exclude);
	port_filters_destroy(&dp->pf_tcp);
	port_filters_destroy(&dp->pf_udp);
	funclist_destroy(&dp->lua_desync);
#ifdef HAS_FILTER_SSID
	strlist_destroy(&dp->filter_ssid);
#endif
	HostFailPoolDestroy(&dp->hostlist_auto_fail_counters);
}
void dp_clear(struct desync_profile *dp)
{
	dp_clear_dynamic(dp);
	memset(dp,0,sizeof(*dp));
}
void dp_entry_destroy(struct desync_profile_list *entry)
{
	dp_clear_dynamic(&entry->dp);
	free(entry);
}
void dp_list_destroy(struct desync_profile_list_head *head)
{
	struct desync_profile_list *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		dp_entry_destroy(entry);
	}
}

static struct desync_profile_list *desync_profile_entry_alloc()
{
	struct desync_profile_list *entry = calloc(1,sizeof(struct desync_profile_list));
	if (entry) dp_init(&entry->dp);
	return entry;
}
struct desync_profile_list *dp_list_add(struct desync_profile_list_head *head)
{
	struct desync_profile_list *entry = desync_profile_entry_alloc();
	if (!entry) return false;

	struct desync_profile_list *tail, *item;
	LIST_TAIL(head, tail, item);
	LIST_INSERT_TAIL(head, tail, entry, next);

	return entry;
}
bool dp_list_copy(struct desync_profile *to, const struct desync_profile *from)
{
	// clear everything in target
	dp_clear(to);
	// first copy all simple type values
	*to = *from;
	// prepare empty dynamic structures
	dp_init_dynamic(to);
	// copy dynamic structures
	if (from->name && !(to->name = strdup(from->name))) return false;
	if (from->name_tpl && !(to->name_tpl = strdup(from->name_tpl))) return false;
	if (from->cookie && !(to->cookie = strdup(from->cookie))) return false;
	if (
#ifdef HAS_FILTER_SSID
		!strlist_copy(&to->filter_ssid, &from->filter_ssid) ||
#endif
		!funclist_copy(&to->lua_desync, &from->lua_desync) ||
		!ipset_collection_copy(&to->ips_collection, &from->ips_collection) ||
		!ipset_collection_copy(&to->ips_collection_exclude, &from->ips_collection_exclude) ||
		!hostlist_collection_copy(&to->hl_collection, &from->hl_collection) ||
		!hostlist_collection_copy(&to->hl_collection_exclude, &from->hl_collection_exclude))
	{
		return false;
	}
	return true;
}
void dp_list_move(struct desync_profile_list_head *target, struct desync_profile_list *dpl)
{
	struct desync_profile_list *tail, *item;
	LIST_TAIL(target, tail, item);
	LIST_REMOVE(dpl, next);
	LIST_INSERT_TAIL(target, tail, dpl, next);
}
struct desync_profile_list *dp_list_search_name(struct desync_profile_list_head *head, const char *name)
{
	struct desync_profile_list *dpl;
	if (name)
		LIST_FOREACH(dpl, head, next)
			if (dpl->dp.name && !strcmp(dpl->dp.name, name))
				return dpl;
	return NULL;
}

bool dp_list_have_autohostlist(struct desync_profile_list_head *head)
{
	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, head, next)
		if (dpl->dp.hostlist_auto)
			return true;
	return false;
}

#if !defined( __OpenBSD__) && !defined(__ANDROID__)
void cleanup_args(struct params_s *params)
{
	wordfree(&params->wexp);
}
#endif

#ifdef __CYGWIN__
void cleanup_windivert_portfilters(struct params_s *params)
{
	char **wdbufs[] =
		{&params->wf_pf_tcp_src_in, &params->wf_pf_tcp_dst_in, &params->wf_pf_udp_src_in, &params->wf_pf_udp_dst_in,
		&params->wf_pf_tcp_src_out, &params->wf_pf_tcp_dst_out, &params->wf_pf_udp_src_out, &params->wf_pf_udp_dst_out};
	for (int i=0 ; i<(sizeof(wdbufs)/sizeof(*wdbufs)) ; i++)
	{
		free(*wdbufs[i]); *wdbufs[i] = NULL;
	}
}
#endif
void cleanup_params(struct params_s *params)
{
	lua_shutdown();

#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	cleanup_args(params);
#endif

	ConntrackPoolDestroy(&params->conntrack);
	dp_list_destroy(&params->desync_profiles);
	dp_list_destroy(&params->desync_templates);
	hostlist_files_destroy(&params->hostlists);
	ipset_files_destroy(&params->ipsets);
	ipcacheDestroy(&params->ipcache);
#ifdef __CYGWIN__
	strlist_destroy(&params->ssid_filter);
	strlist_destroy(&params->nlm_filter);
	strlist_destroy(&params->wf_raw_part);
	cleanup_windivert_portfilters(params);
	free(params->windivert_filter); params->windivert_filter=NULL;
#else
	free(params->user); params->user=NULL;
#endif
}

void init_params(struct params_s *params)
{
	memset(params, 0, sizeof(*params));

#ifdef __linux__
	params->qnum = -1;
#elif defined(BSD)
	params->port = 0;
#endif
	params->desync_fwmark = DPI_DESYNC_FWMARK_DEFAULT;
	params->ctrack_t_syn = CTRACK_T_SYN;
	params->ctrack_t_est = CTRACK_T_EST;
	params->ctrack_t_fin = CTRACK_T_FIN;
	params->ctrack_t_udp = CTRACK_T_UDP;
	params->ipcache_lifetime = IPCACHE_LIFETIME;
	params->lua_gc = LUA_GC_INTERVAL;

	LIST_INIT(&params->hostlists);
	LIST_INIT(&params->ipsets);
	LIST_INIT(&params->blobs);
	LIST_INIT(&params->lua_init_scripts);

#ifdef __CYGWIN__
	LIST_INIT(&params->ssid_filter);
	LIST_INIT(&params->nlm_filter);
	LIST_INIT(&params->wf_raw_part);
#else
	if (can_drop_root())
	{
		params->uid = params->gid[0] = 0x7FFFFFFF; // default uid:gid
		params->gid_count = 1;
		params->droproot = true;
	}
#endif

}
