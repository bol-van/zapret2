#pragma once

#include <stdbool.h>
#include <ctype.h>
#include <sys/queue.h>
#include <net/if.h>

#include "helpers.h"
#include "filter.h"

//#define HASH_BLOOM 20
#define HASH_NONFATAL_OOM 1
#define HASH_FUNCTION HASH_BER
#include "uthash.h"

#include "kavl.h"

#define HOSTLIST_POOL_FLAG_STRICT_MATCH		1

#define LIST_TAIL(head, tail, temp) {\
	tail=LIST_FIRST(head); \
	if (tail) while ((temp=LIST_NEXT(tail,next))) tail = temp; }

#define LIST_INSERT_TAIL(head, tail, elm, field) { \
	if (LIST_FIRST(head)) \
		LIST_INSERT_AFTER(tail, elm, field); \
	else \
		LIST_INSERT_HEAD(head, elm, field); }

#define DESTROY_STR_POOL(etype, ppool) \
	etype *elem, *tmp; \
	HASH_ITER(hh, *ppool, elem, tmp) { \
		free(elem->str); \
		HASH_DEL(*ppool, elem); \
		free(elem); \
	}

#define ADD_STR_POOL(etype, ppool, keystr, keystr_len) \
	etype *elem; \
	if (!(elem = (etype*)malloc(sizeof(etype)))) \
		return false; \
	if (!(elem->str = malloc(keystr_len + 1))) \
	{ \
		free(elem); \
		return NULL; \
	} \
	memcpy(elem->str, keystr, keystr_len); \
	elem->str[keystr_len] = 0; \
	oom = false; \
	HASH_ADD_KEYPTR(hh, *ppool, elem->str, keystr_len, elem); \
	if (oom) \
	{ \
		free(elem->str); \
		free(elem); \
		return NULL; \
	}


typedef struct hostlist_pool {
	char *str;		/* key */
	uint32_t flags;		/* custom data */
	UT_hash_handle hh;	/* makes this structure hashable */
} hostlist_pool;

void HostlistPoolDestroy(hostlist_pool **pp);
bool HostlistPoolAddStr(hostlist_pool **pp, const char *s, uint32_t flags);
bool HostlistPoolAddStrLen(hostlist_pool **pp, const char *s, size_t slen, uint32_t flags);
hostlist_pool *HostlistPoolGetStr(hostlist_pool *p, const char *s);

struct str_list {
	char *str;
	LIST_ENTRY(str_list) next;
};
LIST_HEAD(str_list_head, str_list);

bool strlist_add(struct str_list_head *head, const char *str);
bool strlist_add_tail(struct str_list_head *head, const char *str);
void strlist_destroy(struct str_list_head *head);
bool strlist_search(const struct str_list_head *head, const char *str);
bool strlist_copy(struct str_list_head *to, const struct str_list_head *from);

struct str2_list {
	char *str1,*str2;
	LIST_ENTRY(str2_list) next;
};
LIST_HEAD(str2_list_head, str2_list);

struct str2_list *str2list_add(struct str2_list_head *head);
bool str2list_copy(struct str2_list_head *to, const struct str2_list_head *from);
void str2list_destroy(struct str2_list_head *head);

struct func_list {
	char *func;
	uint64_t payload_type;
	struct packet_range range_in, range_out;
	struct str2_list_head args;
	LIST_ENTRY(func_list) next;
};
LIST_HEAD(func_list_head, func_list);
struct func_list *funclist_add_tail(struct func_list_head *head, const char *func);
bool funclist_copy(struct func_list_head *to, const struct func_list_head *from);
void funclist_destroy(struct func_list_head *head);


typedef struct hostfail_pool {
	char *str;
	int counter;
	time_t expire;	// when to expire record (unixtime)
	UT_hash_handle hh;	/* makes this structure hashable */
} hostfail_pool;

void HostFailPoolDestroy(hostfail_pool **pp);
hostfail_pool *HostFailPoolAdd(hostfail_pool **pp,const char *s,int fail_time);
hostfail_pool *HostFailPoolFind(hostfail_pool *p,const char *s);
void HostFailPoolDel(hostfail_pool **pp, hostfail_pool *elem);
void HostFailPoolPurge(hostfail_pool **pp);
void HostFailPoolPurgeRateLimited(hostfail_pool **pp, time_t *purge_prev);
void HostFailPoolDump(hostfail_pool *p);


struct hostlist_file {
	char *filename;
	file_mod_sig mod_sig;
	hostlist_pool *hostlist;
	LIST_ENTRY(hostlist_file) next;
};
LIST_HEAD(hostlist_files_head, hostlist_file);

struct hostlist_file *hostlist_files_add(struct hostlist_files_head *head, const char *filename);
void hostlist_files_destroy(struct hostlist_files_head *head);
struct hostlist_file *hostlist_files_search(struct hostlist_files_head *head, const char *filename);
void hostlist_files_reset_modtime(struct hostlist_files_head *list);

struct hostlist_item {
	struct hostlist_file *hfile;
	LIST_ENTRY(hostlist_item) next;
};
LIST_HEAD(hostlist_collection_head, hostlist_item);
struct hostlist_item *hostlist_collection_add(struct hostlist_collection_head *head, struct hostlist_file *hfile);
void hostlist_collection_destroy(struct hostlist_collection_head *head);
bool hostlist_collection_copy(struct hostlist_collection_head *to, const struct hostlist_collection_head *from);
struct hostlist_item *hostlist_collection_search(struct hostlist_collection_head *head, const char *filename);
bool hostlist_collection_is_empty(const struct hostlist_collection_head *head);


struct kavl_bit_elem
{
	unsigned int bitlen;
	uint8_t *data;
	KAVL_HEAD(struct kavl_bit_elem) head;
};

struct kavl_bit_elem *kavl_bit_get(const struct kavl_bit_elem *hdr, const void *data, unsigned int bitlen);
struct kavl_bit_elem *kavl_bit_add(struct kavl_bit_elem **hdr, void *data, unsigned int bitlen, size_t struct_size);
void kavl_bit_delete(struct kavl_bit_elem **hdr, const void *data, unsigned int bitlen);
void kavl_bit_destroy(struct kavl_bit_elem **hdr);

// combined ipset ipv4 and ipv6
typedef struct ipset {
	struct kavl_bit_elem *ips4,*ips6;
} ipset;

#define IPSET_EMPTY(ips) (!(ips)->ips4 && !(ips)->ips6)

bool ipset4Add(struct kavl_bit_elem **ipset, const struct in_addr *a, uint8_t preflen);
static inline bool ipset4AddCidr(struct kavl_bit_elem **ipset, const struct cidr4 *cidr)
{
	return ipset4Add(ipset,&cidr->addr,cidr->preflen);
}
bool ipset4Check(const struct kavl_bit_elem *ipset, const struct in_addr *a, uint8_t preflen);
void ipset4Print(struct kavl_bit_elem *ipset);

bool ipset6Add(struct kavl_bit_elem **ipset, const struct in6_addr *a, uint8_t preflen);
static inline bool ipset6AddCidr(struct kavl_bit_elem **ipset, const struct cidr6 *cidr)
{
	return ipset6Add(ipset,&cidr->addr,cidr->preflen);
}
bool ipset6Check(const struct kavl_bit_elem *ipset, const struct in6_addr *a, uint8_t preflen);
void ipset6Print(struct kavl_bit_elem *ipset);

void ipsetDestroy(ipset *ipset);
void ipsetPrint(ipset *ipset);


struct ipset_file {
	char *filename;
	file_mod_sig mod_sig;
	ipset ipset;
	LIST_ENTRY(ipset_file) next;
};
LIST_HEAD(ipset_files_head, ipset_file);

struct ipset_file *ipset_files_add(struct ipset_files_head *head, const char *filename);
void ipset_files_destroy(struct ipset_files_head *head);
struct ipset_file *ipset_files_search(struct ipset_files_head *head, const char *filename);
void ipset_files_reset_modtime(struct ipset_files_head *list);

struct ipset_item {
	struct ipset_file *hfile;
	LIST_ENTRY(ipset_item) next;
};
LIST_HEAD(ipset_collection_head, ipset_item);
struct ipset_item * ipset_collection_add(struct ipset_collection_head *head, struct ipset_file *hfile);
bool ipset_collection_copy(struct ipset_collection_head *to, const struct ipset_collection_head *from);
void ipset_collection_destroy(struct ipset_collection_head *head);
struct ipset_item *ipset_collection_search(struct ipset_collection_head *head, const char *filename);
bool ipset_collection_is_empty(const struct ipset_collection_head *head);


struct port_filter_item {
	port_filter pf;
	LIST_ENTRY(port_filter_item) next;
};
LIST_HEAD(port_filters_head, port_filter_item);
bool port_filter_add(struct port_filters_head *head, const port_filter *pf);
bool port_filters_copy(struct port_filters_head *to, const struct port_filters_head *from);
void port_filters_destroy(struct port_filters_head *head);
bool port_filters_match(const struct port_filters_head *head, uint16_t port);
bool port_filters_deny_if_empty(struct port_filters_head *head);

struct icmp_filter_item {
	icmp_filter icf;
	LIST_ENTRY(icmp_filter_item) next;
};
LIST_HEAD(icmp_filters_head, icmp_filter_item);
bool icmp_filter_add(struct icmp_filters_head *head, const icmp_filter *icf);
bool icmp_filters_copy(struct icmp_filters_head *to, const struct icmp_filters_head *from);
void icmp_filters_destroy(struct icmp_filters_head *head);
bool icmp_filters_match(const struct icmp_filters_head *head, uint8_t type, uint8_t code);
bool icmp_filters_deny_if_empty(struct icmp_filters_head *head);

struct ipp_filter_item {
	ipp_filter ipp;
	LIST_ENTRY(ipp_filter_item) next;
};
LIST_HEAD(ipp_filters_head, ipp_filter_item);
bool ipp_filter_add(struct ipp_filters_head *head, const ipp_filter *ipp);
bool ipp_filters_copy(struct ipp_filters_head *to, const struct ipp_filters_head *from);
void ipp_filters_destroy(struct ipp_filters_head *head);
bool ipp_filters_match(const struct ipp_filters_head *head, uint8_t proto);
bool ipp_filters_deny_if_empty(struct ipp_filters_head *head);

struct blob_item {
	uint8_t *data;	// main data blob
	size_t size;	// main data blob size
	size_t size_buf;// main data blob allocated size
	char *name;  // optional name for search
	void *extra;	// any data without size
	LIST_ENTRY(blob_item) next;
};
LIST_HEAD(blob_collection_head, blob_item);
struct blob_item *blob_collection_add(struct blob_collection_head *head);
struct blob_item *blob_collection_add_blob(struct blob_collection_head *head, const void *data, size_t size, size_t size_reserve);
void blob_destroy(struct blob_item *blob);
void blob_collection_destroy(struct blob_collection_head *head);
bool blob_collection_empty(const struct blob_collection_head *head);
struct blob_item *blob_collection_search_name(struct blob_collection_head *head, const char *name);


typedef struct ip4if
{
	char iface[IFNAMSIZ];
	struct in_addr addr;
} ip4if;
typedef struct ip6if
{
	char iface[IFNAMSIZ];
	struct in6_addr addr;
} ip6if;
typedef struct ip_cache_item
{
	time_t last;
	char *hostname;
	bool hostname_is_ip;
	uint8_t ttl;
	uint8_t fastpath_retrans_count;
} ip_cache_item;
typedef struct ip_cache4
{
	ip4if key;
	ip_cache_item data;
	UT_hash_handle hh;	/* makes this structure hashable */
} ip_cache4;
typedef struct ip_cache6
{
	ip6if key;
	ip_cache_item data;
	UT_hash_handle hh;	/* makes this structure hashable */
} ip_cache6;
typedef struct ip_cache
{
	ip_cache4 *ipcache4;
	ip_cache6 *ipcache6;
} ip_cache;

ip_cache_item *ipcacheTouch(ip_cache *ipcache, const struct in_addr *a4, const struct in6_addr *a6, const char *iface);
ip_cache_item *ipcacheFind(ip_cache *ipcache, const struct in_addr *a4, const struct in6_addr *a6, const char *iface);
void ipcachePurgeRateLimited(ip_cache *ipcache, time_t lifetime);
void ipcacheDestroy(ip_cache *ipcache);
void ipcachePrint(ip_cache *ipcache);
