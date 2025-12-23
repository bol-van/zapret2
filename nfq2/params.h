#pragma once

#include "nfqws.h"
#include "pools.h"
#include "conntrack.h"
#include "desync.h"
#include "protocol.h"
#include "helpers.h"
#include "sec.h"

#include <sys/param.h>
#include <sys/types.h>
#include <net/if.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <sys/queue.h>
#include <lua.h>
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
#include <wordexp.h>
#endif

#define TLS_PARTIALS_ENABLE	true

#define RAW_SNDBUF	(64*1024)	// in bytes

#define Q_MAXLEN	1024		// in packets

#define HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT	3
#define	HOSTLIST_AUTO_FAIL_TIME_DEFAULT 	60
#define	HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT	3
#define HOSTLIST_AUTO_RETRANS_MAXSEQ		32768
#define HOSTLIST_AUTO_INCOMING_MAXSEQ		4096
#define HOSTLIST_AUTO_UDP_OUT			4
#define HOSTLIST_AUTO_UDP_IN			1

#define IPCACHE_LIFETIME		7200

#define MAX_GIDS 64

#define MAX_BLOB_SIZE			(16*1024)
#define BLOB_EXTRA_BYTES		128

// this MSS is used for ipv6 in windows and linux
#define DEFAULT_MSS			1220

#define RECONSTRUCT_MAX_SIZE		16384

#define LUA_GC_INTERVAL			60

extern const char *tld[6];
extern const char *fake_http_request_default;
extern const uint8_t fake_tls_clienthello_default[680];

enum log_target { LOG_TARGET_CONSOLE=0, LOG_TARGET_FILE, LOG_TARGET_SYSLOG, LOG_TARGET_ANDROID };

struct desync_profile
{
	unsigned int n;	// number of the profile
	char *name; // optional malloced name string
	unsigned int n_tpl; // number of imported template
	char *name_tpl; // imported template name
	char *cookie; // optional malloced string

	bool filter_ipv4,filter_ipv6;
	struct port_filters_head pf_tcp,pf_udp;
	uint64_t filter_l7;	// L7_PROTO_* bits

#ifdef HAS_FILTER_SSID
	// per profile ssid filter
	// annot use global filter because it's not possible to bind multiple instances to a single queue
	// it's possible to run multiple winws2 instances on the same windivert filter, but it's not the case for linux
	struct str_list_head filter_ssid;
#endif

	// list of pointers to ipsets
	struct ipset_collection_head ips_collection, ips_collection_exclude;

	// list of pointers to hostlist files
	struct hostlist_collection_head hl_collection, hl_collection_exclude;
	// pointer to autohostlist. NULL if no autohostlist for the profile.
	struct hostlist_file *hostlist_auto;
	int hostlist_auto_fail_threshold, hostlist_auto_fail_time, hostlist_auto_retrans_threshold;
	int hostlist_auto_udp_in, hostlist_auto_udp_out;
	uint32_t hostlist_auto_retrans_maxseq, hostlist_auto_incoming_maxseq;
	bool hostlist_auto_retrans_reset;

	hostfail_pool *hostlist_auto_fail_counters;

	struct func_list_head lua_desync;
};
#define PROFILE_NAME(dp) ((dp)->name ? (dp)->name : "noname")

#define PROFILE_IPSETS_ABSENT(dp) (!LIST_FIRST(&(dp)->ips_collection) && !LIST_FIRST(&(dp)->ips_collection_exclude))
#define PROFILE_IPSETS_EMPTY(dp) (ipset_collection_is_empty(&(dp)->ips_collection) && ipset_collection_is_empty(&(dp)->ips_collection_exclude))
#define PROFILE_HOSTLISTS_EMPTY(dp) (hostlist_collection_is_empty(&(dp)->hl_collection) && hostlist_collection_is_empty(&(dp)->hl_collection_exclude))

struct desync_profile_list {
	struct desync_profile dp;
	LIST_ENTRY(desync_profile_list) next;
};
LIST_HEAD(desync_profile_list_head, desync_profile_list);
struct desync_profile_list *dp_list_add(struct desync_profile_list_head *head);
void dp_list_move(struct desync_profile_list_head *target, struct desync_profile_list *dpl);
bool dp_list_copy(struct desync_profile *to, const struct desync_profile *from);
struct desync_profile_list *dp_list_search_name(struct desync_profile_list_head *head, const char *name);
void dp_entry_destroy(struct desync_profile_list *entry);
void dp_list_destroy(struct desync_profile_list_head *head);
bool dp_list_have_autohostlist(struct desync_profile_list_head *head);
void dp_init(struct desync_profile *dp);
bool dp_fake_defaults(struct desync_profile *dp);
void dp_clear(struct desync_profile *dp);

#define WINDIVERT_MAX 65536
#define WINDIVERT_PORTFILTER_MAX 4096

struct params_s
{
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
	wordexp_t wexp; // for file based config
#endif
	char verstr[128];

	enum log_target debug_target;
	char debug_logfile[PATH_MAX];
	bool debug;

	bool daemon;

#ifdef __linux__
	int qnum;
#elif defined(BSD)
	uint16_t port; // divert port
#endif
	bool bind_fix4,bind_fix6;
	uint32_t desync_fwmark; // unused in BSD
	
	struct desync_profile_list_head desync_profiles, desync_templates;
	
#ifdef __CYGWIN__
	struct str_list_head ssid_filter,nlm_filter;
	struct str_list_head wf_raw_part;

	char *windivert_filter;
	char *wf_pf_tcp_src_in, *wf_pf_tcp_dst_in, *wf_pf_udp_src_in, *wf_pf_udp_dst_in;
	char *wf_pf_tcp_src_out, *wf_pf_tcp_dst_out, *wf_pf_udp_src_out, *wf_pf_udp_dst_out;
#else
	bool droproot;
	char *user;
	uid_t uid;
	gid_t gid[MAX_GIDS];
	int gid_count;
#endif
	char pidfile[PATH_MAX];

	char hostlist_auto_debuglog[PATH_MAX];

	// hostlist files with data for all profiles
	struct hostlist_files_head hostlists;
	// ipset files with data for all profiles
	struct ipset_files_head ipsets;

	// LUA var blobs
	struct blob_collection_head blobs;

	unsigned int ctrack_t_syn, ctrack_t_est, ctrack_t_fin, ctrack_t_udp;
	t_conntrack conntrack;
	bool ctrack_disable, server;

#ifdef HAS_FILTER_SSID
	bool filter_ssid_present;
#endif

	bool cache_hostname;
	unsigned int ipcache_lifetime;
	ip_cache ipcache;
	uint64_t reasm_payload_disable;

	struct str_list_head lua_init_scripts;
	bool writeable_dir_enable;
	char writeable_dir[PATH_MAX];

	int lua_gc;
	lua_State *L;
};

extern struct params_s params;
extern const char *progname;

void init_params(struct params_s *params);
#if !defined( __OpenBSD__) && !defined(__ANDROID__)
void cleanup_args(struct params_s *params);
#endif
#ifdef __CYGWIN__
void cleanup_windivert_portfilters(struct params_s *params);
#endif
void cleanup_params(struct params_s *params);

int DLOG(const char *format, ...);
int DLOG_ERR(const char *format, ...);
int DLOG_PERROR(const char *s);
int DLOG_CONDUP(const char *format, ...);
int HOSTLIST_DEBUGLOG_APPEND(const char *format, ...);
void hexdump_limited_dlog(const uint8_t *data, size_t size, size_t limit);
