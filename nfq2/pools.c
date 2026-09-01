#define _GNU_SOURCE
#include "pools.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ADD_HOSTLIST_POOL(etype, ppool, keystr, keystr_len, flg) \
	etype *elem_find; \
	HASH_FIND(hh, *ppool, keystr, keystr_len, elem_find); \
	if (!elem_find) { \
		ADD_STR_POOL(etype,ppool,keystr,keystr_len); \
		elem->flags = flg; \
	}

#undef uthash_nonfatal_oom
#define uthash_nonfatal_oom(elt) ut_oom_recover(elt)
static bool oom = false;
static void ut_oom_recover(void *elem)
{
	oom = true;
}

// for not zero terminated strings
bool HostlistPoolAddStrLen(hostlist_pool **pp, const char *s, size_t slen, uint32_t flags)
{
	ADD_HOSTLIST_POOL(hostlist_pool, pp, s, slen, flags)
	return true;
}
// for zero terminated strings
bool HostlistPoolAddStr(hostlist_pool **pp, const char *s, uint32_t flags)
{
	return HostlistPoolAddStrLen(pp, s, strlen(s), flags);
}

hostlist_pool *HostlistPoolGetStr(hostlist_pool *p, const char *s)
{
	hostlist_pool *elem;
	HASH_FIND_STR(p, s, elem);
	return elem;
}
bool HostlistPoolCheckStr(hostlist_pool *p, const char *s)
{
	return HostlistPoolGetStr(p,s);
}

void HostlistPoolDestroy(hostlist_pool **pp)
{
	DESTROY_STR_POOL(hostlist_pool, pp)
}



void HostFailPoolDestroy(hostfail_pool **pp)
{
	DESTROY_STR_POOL(hostfail_pool, pp)
}
hostfail_pool * HostFailPoolAdd(hostfail_pool **pp,const char *s,int fail_time)
{
	size_t slen = strlen(s);
	ADD_STR_POOL(hostfail_pool, pp, s, slen)
	elem->expire = boottime() + fail_time;
	elem->counter = 0;
	return elem;
}
hostfail_pool *HostFailPoolFind(hostfail_pool *p,const char *s)
{
	hostfail_pool *elem;
	HASH_FIND_STR(p, s, elem);
	return elem;
}
void HostFailPoolDel(hostfail_pool **p, hostfail_pool *elem)
{
	free(elem->str);
	HASH_DEL(*p, elem);
	free(elem);
}
void HostFailPoolPurge(hostfail_pool **pp)
{
	hostfail_pool *elem, *tmp;
	time_t now = boottime();
	HASH_ITER(hh, *pp, elem, tmp)
	{
		if (now >= elem->expire)
			HostFailPoolDel(pp, elem);
	}
}
void HostFailPoolPurgeRateLimited(hostfail_pool **pp, time_t *purge_prev)
{
	time_t now = boottime();
	// do not purge too often to save resources
	if (*purge_prev != now)
	{
		HostFailPoolPurge(pp);
		*purge_prev = now;
	}
}
void HostFailPoolDump(hostfail_pool *p)
{
	hostfail_pool *elem, *tmp;
	time_t now = boottime();
	HASH_ITER(hh, p, elem, tmp)
		printf("host=%s counter=%d time_left=%lld\n",elem->str,elem->counter,(long long int)elem->expire-now);
}


static struct str_list *strlist_entry_alloc(const char *str)
{
	struct str_list *entry = malloc(sizeof(struct str_list));
	if (!entry) return NULL;
	if (str)
	{
		if (!(entry->str = strdup(str)))
		{
			free(entry);
			return NULL;
		}
	}
	else
		entry->str = NULL;
	return entry;
}

bool strlist_add(struct str_list_head *head, const char *str)
{
	struct str_list *entry = strlist_entry_alloc(str);
	if (!entry) return false;
	LIST_INSERT_HEAD(head, entry, next);
	return true;
}
static struct str_list *strlist_entry_copy(const struct str_list *entry)
{
	return strlist_entry_alloc(entry->str);
}
bool strlist_copy(struct str_list_head *to, const struct str_list_head *from)
{
	struct str_list *tail, *item, *entry;

	LIST_TAIL(to, tail, item);
	LIST_FOREACH(item, from, next)
	{
		if (!(entry = strlist_entry_copy(item))) return false;
		LIST_INSERT_TAIL(to, tail, entry, next);
		tail = tail ? LIST_NEXT(tail, next) : LIST_FIRST(to);
	}
	return true;
}

bool strlist_add_tail(struct str_list_head *head, const char *str)
{
	struct str_list *entry = strlist_entry_alloc(str);
	if (!entry) return false;

	struct str_list *tail, *item;
	LIST_TAIL(head, tail, item);
	LIST_INSERT_TAIL(head, tail, entry, next);

	return true;
}
static void strlist_entry_destroy(struct str_list *entry)
{
	free(entry->str);
	free(entry);
}
void strlist_destroy(struct str_list_head *head)
{
	struct str_list *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		strlist_entry_destroy(entry);
	}
}
bool strlist_search(const struct str_list_head *head, const char *str)
{
	struct str_list *entry;
	if (str)
	{
		LIST_FOREACH(entry, head, next)
		{
			if (!strcmp(entry->str, str))
				return true;
		}
	}
	return false;
}


static void str2list_entry_destroy(struct str2_list *entry)
{
	free(entry->str1);
	free(entry->str2);
	free(entry);
}
void str2list_destroy(struct str2_list_head *head)
{
	struct str2_list *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		str2list_entry_destroy(entry);
	}
}
static struct str2_list *str2list_entry_alloc()
{
	return (struct str2_list*)calloc(1,sizeof(struct str2_list));
}

struct str2_list *str2list_add(struct str2_list_head *head)
{
	struct str2_list *entry = str2list_entry_alloc();
	if (!entry) return NULL;
	LIST_INSERT_HEAD(head, entry, next);
	return entry;
}
static struct str2_list *str2list_entry_copy(const struct str2_list *entry)
{
	struct str2_list *e2 = str2list_entry_alloc();
	if (!e2) return NULL;

	if (entry->str1) if (!(e2->str1 = strdup(entry->str1))) goto err;
	if (entry->str2) if (!(e2->str2 = strdup(entry->str2))) goto err;
	return e2;
err:
	str2list_entry_destroy(e2);
	return NULL;
}
bool str2list_copy(struct str2_list_head *to, const struct str2_list_head *from)
{
	struct str2_list *tail, *item, *entry;

	LIST_TAIL(to, tail, item);
	LIST_FOREACH(item, from, next)
	{
		if (!(entry = str2list_entry_copy(item))) return false;
		LIST_INSERT_TAIL(to, tail, entry, next);
		tail = tail ? LIST_NEXT(tail, next) : LIST_FIRST(to);
	}
	return true;
}



static void funclist_entry_destroy(struct func_list *entry)
{
	free(entry->func);
	str2list_destroy(&entry->args);
	free(entry);
}
void funclist_destroy(struct func_list_head *head)
{
	struct func_list *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		funclist_entry_destroy(entry);
	}
}
static struct func_list *funclist_entry_alloc(const char *func)
{
	struct func_list *entry = malloc(sizeof(struct func_list));
	if (!entry) return NULL;
	entry->func = strdup(func);
	if (!entry->func)
	{
		free(entry);
		return NULL;
	}
	entry->payload_type = 0;
	entry->range_in = entry->range_out = PACKET_RANGE_ALWAYS;
	LIST_INIT(&entry->args);
	return entry;
}

struct func_list *funclist_add_tail(struct func_list_head *head, const char *func)
{
	struct func_list *entry = funclist_entry_alloc(func);
	if (!entry) return NULL;

	struct func_list *tail, *item;
	LIST_TAIL(head, tail, item);
	LIST_INSERT_TAIL(head, tail, entry, next);

	return entry;
}
static struct func_list *funclist_entry_copy(const struct func_list *entry)
{
	struct func_list *e2 = funclist_entry_alloc(entry->func);
	if (!e2) return NULL;
	e2->payload_type = entry->payload_type;
	e2->range_in = entry->range_in;
	e2->range_out = entry->range_out;
	if (!str2list_copy(&e2->args, &entry->args))
	{
		funclist_entry_destroy(e2);
		return NULL;
	}
	return e2;
}
bool funclist_copy(struct func_list_head *to, const struct func_list_head *from)
{
	struct func_list *tail, *item, *entry;

	LIST_TAIL(to, tail, item);
	LIST_FOREACH(item, from, next)
	{
		if (!(entry = funclist_entry_copy(item))) return false;
		LIST_INSERT_TAIL(to, tail, entry, next);
		tail = tail ? LIST_NEXT(tail, next) : LIST_FIRST(to);
	}
	return true;
}


struct hostlist_file *hostlist_files_add(struct hostlist_files_head *head, const char *filename)
{
	struct hostlist_file *entry = malloc(sizeof(struct hostlist_file));
	if (entry)
	{
		if (filename)
		{
			if (!(entry->filename = strdup(filename)))
			{
				free(entry);
				return NULL;
			}
		}
		else
			entry->filename = NULL;
		FILE_MOD_RESET(&entry->mod_sig);
		entry->hostlist = NULL;
		LIST_INSERT_HEAD(head, entry, next);
	}
	return entry;
}
static void hostlist_files_entry_destroy(struct hostlist_file *entry)
{
	free(entry->filename);
	HostlistPoolDestroy(&entry->hostlist);
	free(entry);
}
void hostlist_files_destroy(struct hostlist_files_head *head)
{
	struct hostlist_file *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		hostlist_files_entry_destroy(entry);
	}
}
struct hostlist_file *hostlist_files_search(struct hostlist_files_head *head, const char *filename)
{
	struct hostlist_file *hfile;

	LIST_FOREACH(hfile, head, next)
	{
		if (hfile->filename && !strcmp(hfile->filename,filename))
			return hfile;
	}
	return NULL;
}
void hostlist_files_reset_modtime(struct hostlist_files_head *list)
{
	struct hostlist_file *hfile;

	LIST_FOREACH(hfile, list, next)
		FILE_MOD_RESET(&hfile->mod_sig);
}

static struct hostlist_item *hostlist_collection_entry_alloc(struct hostlist_file *hfile)
{
	struct hostlist_item *entry = malloc(sizeof(struct hostlist_item));
	if (entry) entry->hfile = hfile;
	return entry;
}
struct hostlist_item *hostlist_collection_add(struct hostlist_collection_head *head, struct hostlist_file *hfile)
{
	struct hostlist_item *entry = hostlist_collection_entry_alloc(hfile);
	if (entry) LIST_INSERT_HEAD(head, entry, next);
	return entry;
}
static struct hostlist_item *hostlist_collection_entry_copy(const struct hostlist_item *entry)
{
	return hostlist_collection_entry_alloc(entry->hfile);
}
bool hostlist_collection_copy(struct hostlist_collection_head *to, const struct hostlist_collection_head *from)
{
	struct hostlist_item *tail, *item, *entry;

	LIST_TAIL(to, tail, item);
	LIST_FOREACH(item, from, next)
	{
		if (!(entry = hostlist_collection_entry_copy(item))) return false;
		LIST_INSERT_TAIL(to, tail, entry, next);
		tail = tail ? LIST_NEXT(tail, next) : LIST_FIRST(to);
	}
	return true;
}

void hostlist_collection_destroy(struct hostlist_collection_head *head)
{
	struct hostlist_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		free(entry);
	}
}
struct hostlist_item *hostlist_collection_search(struct hostlist_collection_head *head, const char *filename)
{
	struct hostlist_item *item;

	LIST_FOREACH(item, head, next)
	{
		if (item->hfile->filename && !strcmp(item->hfile->filename,filename))
			return item;
	}
	return NULL;
}
bool hostlist_collection_is_empty(const struct hostlist_collection_head *head)
{
	const struct hostlist_item *item;

	LIST_FOREACH(item, head, next)
	{
		if (item->hfile->hostlist)
			return false;
	}
	return true;
}


static int kavl_bit_cmp(const struct kavl_bit_elem *p, const struct kavl_bit_elem *q)
{
	unsigned int bitlen = q->bitlen < p->bitlen ? q->bitlen : p->bitlen;
	unsigned int df = bitlen & 7, bytes = bitlen >> 3;
	int cmp = memcmp(p->data, q->data, bytes);

	if (cmp || !df) return cmp;

	uint8_t c1 = p->data[bytes] >> (8 - df);
	uint8_t c2 = q->data[bytes] >> (8 - df);
	return c1<c2 ? -1 : c1==c2 ? 0 : 1;
}
KAVL_INIT(kavl_bit, struct kavl_bit_elem, head, kavl_bit_cmp)
static void kavl_bit_destroy_elem(struct kavl_bit_elem *e)
{
	if (e)
	{
		free(e->data);
		free(e);
	}
}
void kavl_bit_delete(struct kavl_bit_elem **hdr, const void *data, unsigned int bitlen)
{
	struct kavl_bit_elem temp = {
		.bitlen = bitlen, .data = (uint8_t*)data
	};
	kavl_bit_destroy_elem(kavl_erase(kavl_bit, hdr, &temp, 0));
}
void kavl_bit_destroy(struct kavl_bit_elem **hdr)
{
	while (*hdr)
	{
		struct kavl_bit_elem *e = kavl_erase_first(kavl_bit, hdr);
		if (!e)	break;
		kavl_bit_destroy_elem(e);
	}
}
struct kavl_bit_elem *kavl_bit_add(struct kavl_bit_elem **hdr, void *data, unsigned int bitlen, size_t struct_size)
{
	if (!struct_size) struct_size=sizeof(struct kavl_bit_elem);

	struct kavl_bit_elem *v, *e = calloc(1, struct_size);
	if (!e) return 0;

	e->bitlen = bitlen;
	e->data = data;

	v = kavl_insert(kavl_bit, hdr, e, 0);
	while (e != v && e->bitlen < v->bitlen)
	{
		kavl_bit_delete(hdr, v->data, v->bitlen);
		v = kavl_insert(kavl_bit, hdr, e, 0);
	}
	if (e != v) kavl_bit_destroy_elem(e);
	return v;
}
struct kavl_bit_elem *kavl_bit_get(const struct kavl_bit_elem *hdr, const void *data, unsigned int bitlen)
{
	struct kavl_bit_elem temp = {
		.bitlen = bitlen, .data = (uint8_t*)data
	};
	return kavl_find(kavl_bit, hdr, &temp, 0);
}

static bool ipset_kavl_add(struct kavl_bit_elem **ipset, const void *a, uint8_t preflen)
{
	uint8_t *abuf, bytelen = (preflen+7)>>3;
	if (bytelen)
	{
		abuf = malloc(bytelen);
		if (!abuf) return false;
		memcpy(abuf,a,bytelen);
	}
	else
		abuf = NULL;
	if (!kavl_bit_add(ipset,abuf,preflen,0))
	{
		free(abuf);
		return false;
	}
	return true;
}


bool ipset4Check(const struct kavl_bit_elem *ipset, const struct in_addr *a, uint8_t preflen)
{
	return kavl_bit_get(ipset,a,preflen);
}
bool ipset4Add(struct kavl_bit_elem **ipset, const struct in_addr *a, uint8_t preflen)
{
	if (preflen>32) return false;
	return ipset_kavl_add(ipset,a,preflen);
}
void ipset4Print(struct kavl_bit_elem *ipset)
{
	if (!ipset) return;

	struct cidr4 c;
	const struct kavl_bit_elem *elem;
	kavl_itr_t(kavl_bit) itr;
	kavl_itr_first(kavl_bit, ipset, &itr);
	do
	{
		elem = kavl_at(&itr);
		c.preflen = elem->bitlen;
		expand_bits(&c.addr, elem->data, elem->bitlen, sizeof(c.addr));
		print_cidr4(&c);
		printf("\n");
	}
	while (kavl_itr_next(kavl_bit, &itr));
}

bool ipset6Check(const struct kavl_bit_elem *ipset, const struct in6_addr *a, uint8_t preflen)
{
	return kavl_bit_get(ipset,a,preflen);
}
bool ipset6Add(struct kavl_bit_elem **ipset, const struct in6_addr *a, uint8_t preflen)
{
	if (preflen>128) return false;
	return ipset_kavl_add(ipset,a,preflen);
}
void ipset6Print(struct kavl_bit_elem *ipset)
{
	if (!ipset) return;

	struct cidr6 c;
	const struct kavl_bit_elem *elem;
	kavl_itr_t(kavl_bit) itr;
	kavl_itr_first(kavl_bit, ipset, &itr);
	do
	{
		elem = kavl_at(&itr);
		c.preflen = elem->bitlen;
		expand_bits(&c.addr, elem->data, elem->bitlen, sizeof(c.addr));
		print_cidr6(&c);
		printf("\n");
	}
	while (kavl_itr_next(kavl_bit, &itr));
}

void ipsetDestroy(ipset *ipset)
{
	kavl_bit_destroy(&ipset->ips4);
	kavl_bit_destroy(&ipset->ips6);
}
void ipsetPrint(ipset *ipset)
{
	ipset4Print(ipset->ips4);
	ipset6Print(ipset->ips6);
}


struct ipset_file *ipset_files_add(struct ipset_files_head *head, const char *filename)
{
	struct ipset_file *entry = malloc(sizeof(struct ipset_file));
	if (entry)
	{
		if (filename)
		{
			if (!(entry->filename = strdup(filename)))
			{
				free(entry);
				return NULL;
			}
		}
		else
			entry->filename = NULL;
		FILE_MOD_RESET(&entry->mod_sig);
		memset(&entry->ipset,0,sizeof(entry->ipset));
		LIST_INSERT_HEAD(head, entry, next);
	}
	return entry;
}
static void ipset_files_entry_destroy(struct ipset_file *entry)
{
	free(entry->filename);
	ipsetDestroy(&entry->ipset);
	free(entry);
}
void ipset_files_destroy(struct ipset_files_head *head)
{
	struct ipset_file *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		ipset_files_entry_destroy(entry);
	}
}
struct ipset_file *ipset_files_search(struct ipset_files_head *head, const char *filename)
{
	struct ipset_file *hfile;

	LIST_FOREACH(hfile, head, next)
	{
		if (hfile->filename && !strcmp(hfile->filename,filename))
			return hfile;
	}
	return NULL;
}
void ipset_files_reset_modtime(struct ipset_files_head *list)
{
	struct ipset_file *hfile;

	LIST_FOREACH(hfile, list, next)
		FILE_MOD_RESET(&hfile->mod_sig);
}

static struct ipset_item *ipset_collection_entry_alloc(struct ipset_file *hfile)
{
	struct ipset_item *entry = malloc(sizeof(struct ipset_item));
	if (entry) entry->hfile = hfile;
	return entry;
}
struct ipset_item *ipset_collection_add(struct ipset_collection_head *head, struct ipset_file *hfile)
{
	struct ipset_item *entry = ipset_collection_entry_alloc(hfile);
	if (entry) LIST_INSERT_HEAD(head, entry, next);
	return entry;
}
static struct ipset_item *ipset_collection_entry_copy(const struct ipset_item *entry)
{
	return ipset_collection_entry_alloc(entry->hfile);
}
bool ipset_collection_copy(struct ipset_collection_head *to, const struct ipset_collection_head *from)
{
	struct ipset_item *tail, *item, *entry;

	LIST_TAIL(to, tail, item);
	LIST_FOREACH(item, from, next)
	{
		if (!(entry = ipset_collection_entry_copy(item))) return false;
		LIST_INSERT_TAIL(to, tail, entry, next);
		tail = tail ? LIST_NEXT(tail, next) : LIST_FIRST(to);
	}
	return true;
}

void ipset_collection_destroy(struct ipset_collection_head *head)
{
	struct ipset_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		free(entry);
	}
}
struct ipset_item *ipset_collection_search(struct ipset_collection_head *head, const char *filename)
{
	struct ipset_item *item;

	LIST_FOREACH(item, head, next)
	{
		if (item->hfile->filename && !strcmp(item->hfile->filename,filename))
			return item;
	}
	return NULL;
}
bool ipset_collection_is_empty(const struct ipset_collection_head *head)
{
	const struct ipset_item *item;

	LIST_FOREACH(item, head, next)
	{
		if (!IPSET_EMPTY(&item->hfile->ipset))
			return false;
	}
	return true;
}


static struct port_filter_item *port_filter_entry_alloc(const port_filter *pf)
{
	struct port_filter_item *entry = malloc(sizeof(struct port_filter_item));
	if (entry) entry->pf = *pf;
	return entry;
}
bool port_filter_add(struct port_filters_head *head, const port_filter *pf)
{
	struct port_filter_item *entry = port_filter_entry_alloc(pf);
	if (entry) LIST_INSERT_HEAD(head, entry, next);
	return entry;
}
static struct port_filter_item *port_filter_entry_copy(const struct port_filter_item *pfi)
{
	return port_filter_entry_alloc(&pfi->pf);
}
bool port_filters_copy(struct port_filters_head *to, const struct port_filters_head *from)
{
	struct port_filter_item *tail, *item, *entry;

	LIST_TAIL(to, tail, item);
	LIST_FOREACH(item, from, next)
	{
		if (!(entry = port_filter_entry_copy(item))) return false;
		LIST_INSERT_TAIL(to, tail, entry, next);
		tail = tail ? LIST_NEXT(tail, next) : LIST_FIRST(to);
	}
	return true;
}
void port_filters_destroy(struct port_filters_head *head)
{
	struct port_filter_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		free(entry);
	}
}
bool port_filters_match(const struct port_filters_head *head, uint16_t port)
{
	const struct port_filter_item *item;

	if (LIST_EMPTY(head)) return true;
	LIST_FOREACH(item, head, next)
	{
		if (pf_match(port, &item->pf))
			return true;
	}
	return false;
}
bool port_filters_deny_if_empty(struct port_filters_head *head)
{
	port_filter pf;
	if (!LIST_EMPTY(head)) return true;
	return pf_parse("0",&pf) && port_filter_add(head,&pf);
}


static struct icmp_filter_item *icmp_filter_entry_alloc(const icmp_filter *icf)
{
	struct icmp_filter_item *entry = malloc(sizeof(struct icmp_filter_item));
	if (entry) entry->icf = *icf;
	return entry;
}
bool icmp_filter_add(struct icmp_filters_head *head, const icmp_filter *icf)
{
	struct icmp_filter_item *entry = icmp_filter_entry_alloc(icf);
	if (entry) LIST_INSERT_HEAD(head, entry, next);
	return entry;
}
static struct icmp_filter_item *icmp_filter_entry_copy(const struct icmp_filter_item *ifi)
{
	return icmp_filter_entry_alloc(&ifi->icf);
}
bool icmp_filters_copy(struct icmp_filters_head *to, const struct icmp_filters_head *from)
{
	struct icmp_filter_item *tail, *item, *entry;

	LIST_TAIL(to, tail, item);
	LIST_FOREACH(item, from, next)
	{
		if (!(entry = icmp_filter_entry_copy(item))) return false;
		LIST_INSERT_TAIL(to, tail, entry, next);
		tail = tail ? LIST_NEXT(tail, next) : LIST_FIRST(to);
	}
	return true;
}
void icmp_filters_destroy(struct icmp_filters_head *head)
{
	struct icmp_filter_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		free(entry);
	}
}
bool icmp_filters_match(const struct icmp_filters_head *head, uint8_t type, uint8_t code)
{
	const struct icmp_filter_item *item;

	if (LIST_EMPTY(head)) return true;
	LIST_FOREACH(item, head, next)
	{
		if (icf_match(type, code, &item->icf))
			return true;
	}
	return false;
}
bool icmp_filters_deny_if_empty(struct icmp_filters_head *head)
{
	icmp_filter icf;
	if (!LIST_EMPTY(head)) return true;
	return icf_parse("-",&icf) && icmp_filter_add(head,&icf);
}


static struct ipp_filter_item *ipp_filter_entry_alloc(const ipp_filter *ipp)
{
	struct ipp_filter_item *entry = malloc(sizeof(struct ipp_filter_item));
	if (entry) entry->ipp = *ipp;
	return entry;
}
bool ipp_filter_add(struct ipp_filters_head *head, const ipp_filter *ipp)
{
	struct ipp_filter_item *entry = ipp_filter_entry_alloc(ipp);
	if (entry) LIST_INSERT_HEAD(head, entry, next);
	return entry;
}
static struct ipp_filter_item *ipp_filter_entry_copy(const struct ipp_filter_item *ifi)
{
	return ipp_filter_entry_alloc(&ifi->ipp);
}
bool ipp_filters_copy(struct ipp_filters_head *to, const struct ipp_filters_head *from)
{
	struct ipp_filter_item *tail, *item, *entry;

	LIST_TAIL(to, tail, item);
	LIST_FOREACH(item, from, next)
	{
		if (!(entry = ipp_filter_entry_copy(item))) return false;
		LIST_INSERT_TAIL(to, tail, entry, next);
		tail = tail ? LIST_NEXT(tail, next) : LIST_FIRST(to);
	}
	return true;
}
void ipp_filters_destroy(struct ipp_filters_head *head)
{
	struct ipp_filter_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		free(entry);
	}
}
bool ipp_filters_match(const struct ipp_filters_head *head, uint8_t proto)
{
	const struct ipp_filter_item *item;

	if (LIST_EMPTY(head)) return true;
	LIST_FOREACH(item, head, next)
	{
		if (ipp_match(proto, &item->ipp))
			return true;
	}
	return false;
}
bool ipp_filters_deny_if_empty(struct ipp_filters_head *head)
{
	ipp_filter ipp;
	if (!LIST_EMPTY(head)) return true;
	return ipp_parse("-",&ipp) && ipp_filter_add(head,&ipp);
}

		
struct blob_item *blob_collection_add(struct blob_collection_head *head)
{
	struct blob_item *entry = calloc(1,sizeof(struct blob_item));
	if (entry)
	{
		struct blob_item *tail, *item;
		LIST_TAIL(head, tail, item);
		LIST_INSERT_TAIL(head, tail, entry, next);
	}
	return entry;
}
struct blob_item *blob_collection_add_blob(struct blob_collection_head *head, const void *data, size_t size, size_t size_reserve)
{
	struct blob_item *entry = calloc(1,sizeof(struct blob_item));
	if (!entry) return NULL;
	if (size+size_reserve)
	{
		if (!(entry->data = malloc(size+size_reserve)))
		{
			free(entry);
			return NULL;
		}
		if (data) memcpy(entry->data,data,size);
	}
	entry->size = size;
	entry->size_buf = size+size_reserve;

	// insert to the end
	struct blob_item *tail, *item;
	LIST_TAIL(head, tail, item);
	LIST_INSERT_TAIL(head, tail, entry, next);

	return entry;
}
void blob_destroy(struct blob_item *blob)
{
	if (blob)
	{
		free(blob->extra);
		free(blob->name);
		free(blob->data);
		free(blob);
	}
}
void blob_collection_destroy(struct blob_collection_head *head)
{
	struct blob_item *entry;
	while ((entry = LIST_FIRST(head)))
	{
		LIST_REMOVE(entry, next);
		blob_destroy(entry);
	}
}
bool blob_collection_empty(const struct blob_collection_head *head)
{
	return LIST_EMPTY(head);
}
struct blob_item *blob_collection_search_name(struct blob_collection_head *head, const char *name)
{
	struct blob_item *blob;
	LIST_FOREACH(blob, head, next)
	{
		if (blob->name && !strcmp(blob->name,name))
			return blob;
	}
	return NULL;
}



static void ipcache_item_touch(ip_cache_item *item)
{
	item->last = boottime();
}
static void ipcache_item_init(ip_cache_item *item)
{
	ipcache_item_touch(item);
	item->hostname = NULL;
	item->hostname_is_ip = false;
	item->ttl = 0;
	item->fastpath_retrans_count = 0;
}
static void ipcache_item_destroy(ip_cache_item *item)
{
	free(item->hostname);
}

static void ipcache4Destroy(ip_cache4 **ipcache)
{
	ip_cache4 *elem, *tmp;
	HASH_ITER(hh, *ipcache, elem, tmp)
	{
		HASH_DEL(*ipcache, elem);
		ipcache_item_destroy(&elem->data);
		free(elem);
	}
}
static void ipcache4Key(ip4if *key, const struct in_addr *a, const char *iface)
{
	memset(key,0,sizeof(*key)); // make sure everything is zero
	key->addr = *a;
	if (iface) snprintf(key->iface,sizeof(key->iface),"%s",iface);
}
static ip_cache4 *ipcache4Find(ip_cache4 *ipcache, const struct in_addr *a, const char *iface)
{
	ip_cache4 *entry;
	struct ip4if key;

	ipcache4Key(&key,a,iface);
	HASH_FIND(hh, ipcache, &key, sizeof(key), entry);
	return entry;
}
static ip_cache4 *ipcache4Add(ip_cache4 **ipcache, const struct in_addr *a, const char *iface)
{
	// avoid dups
	ip_cache4 *entry = ipcache4Find(*ipcache,a,iface);
	if (entry) return entry; // already included

	entry = malloc(sizeof(ip_cache4));
	if (!entry) return NULL;
	ipcache4Key(&entry->key,a,iface);

	oom = false;
	HASH_ADD(hh, *ipcache, key, sizeof(entry->key), entry);
	if (oom) { free(entry); return NULL; }

	ipcache_item_init(&entry->data);

	return entry;
}
static void ipcache4Print(ip_cache4 *ipcache)
{
	char s_ip[INET_ADDRSTRLEN];
	time_t now;
	ip_cache4 *ipc, *tmp;

	now = boottime();
	HASH_ITER(hh, ipcache , ipc, tmp)
	{
		*s_ip=0;
		inet_ntop(AF_INET, &ipc->key.addr, s_ip, sizeof(s_ip));
		printf("%s iface=%s : ttl %u hostname=%s hostname_is_ip=%u fastpath_retrans=%u now=last+%llu\n", s_ip, ipc->key.iface, ipc->data.ttl, ipc->data.hostname ? ipc->data.hostname : "", ipc->data.hostname_is_ip, ipc->data.fastpath_retrans_count, (unsigned long long)(now-ipc->data.last));
	}
}

static void ipcache6Destroy(ip_cache6 **ipcache)
{
	ip_cache6 *elem, *tmp;
	HASH_ITER(hh, *ipcache, elem, tmp)
	{
		HASH_DEL(*ipcache, elem);
		ipcache_item_destroy(&elem->data);
		free(elem);
	}
}
static void ipcache6Key(ip6if *key, const struct in6_addr *a, const char *iface)
{
	memset(key,0,sizeof(*key)); // make sure everything is zero
	key->addr = *a;
	if (iface) snprintf(key->iface,sizeof(key->iface),"%s",iface);
}
static ip_cache6 *ipcache6Find(ip_cache6 *ipcache, const struct in6_addr *a, const char *iface)
{
	ip_cache6 *entry;
	ip6if key;

	ipcache6Key(&key,a,iface);
	HASH_FIND(hh, ipcache, &key, sizeof(key), entry);
	return entry;
}
static ip_cache6 *ipcache6Add(ip_cache6 **ipcache, const struct in6_addr *a, const char *iface)
{
	// avoid dups
	ip_cache6 *entry = ipcache6Find(*ipcache,a,iface);
	if (entry) return entry; // already included

	entry = malloc(sizeof(ip_cache6));
	if (!entry) return NULL;
	ipcache6Key(&entry->key,a,iface);

	oom = false;
	HASH_ADD(hh, *ipcache, key, sizeof(entry->key), entry);
	if (oom) { free(entry); return NULL; }

	ipcache_item_init(&entry->data);

	return entry;
}
static void ipcache6Print(ip_cache6 *ipcache)
{
	char s_ip[INET6_ADDRSTRLEN];
	time_t now;
	ip_cache6 *ipc, *tmp;

	now = boottime();
	HASH_ITER(hh, ipcache , ipc, tmp)
	{
		*s_ip=0;
		inet_ntop(AF_INET6, &ipc->key.addr, s_ip, sizeof(s_ip));
		printf("%s iface=%s : ttl %u hostname=%s hostname_is_ip=%u fastpath_retrans=%u now=last+%llu\n", s_ip, ipc->key.iface, ipc->data.ttl, ipc->data.hostname ? ipc->data.hostname : "", ipc->data.hostname_is_ip, ipc->data.fastpath_retrans_count, (unsigned long long)(now-ipc->data.last));
	}
}

void ipcacheDestroy(ip_cache *ipcache)
{
	ipcache4Destroy(&ipcache->ipcache4);
	ipcache6Destroy(&ipcache->ipcache6);
}
void ipcachePrint(ip_cache *ipcache)
{
	ipcache4Print(ipcache->ipcache4);
	ipcache6Print(ipcache->ipcache6);
}

ip_cache_item *ipcacheFind(ip_cache *ipcache, const struct in_addr *a4, const struct in6_addr *a6, const char *iface)
{
	ip_cache4 *ipcache4;
	ip_cache6 *ipcache6;
	if (a4)
	{
		if ((ipcache4 = ipcache4Find(ipcache->ipcache4,a4,iface)))
			return &ipcache4->data;
	}
	else if (a6)
	{
		if ((ipcache6 = ipcache6Find(ipcache->ipcache6,a6,iface)))
			return &ipcache6->data;
	}
	return NULL;
}
ip_cache_item *ipcacheTouch(ip_cache *ipcache, const struct in_addr *a4, const struct in6_addr *a6, const char *iface)
{
	ip_cache4 *ipcache4;
	ip_cache6 *ipcache6;
	if (a4)
	{
		if ((ipcache4 = ipcache4Add(&ipcache->ipcache4,a4,iface)))
		{
			ipcache_item_touch(&ipcache4->data);
			return &ipcache4->data;
		}
	}
	else if (a6)
	{
		if ((ipcache6 = ipcache6Add(&ipcache->ipcache6,a6,iface)))
		{
			ipcache_item_touch(&ipcache6->data);
			return &ipcache6->data;
		}
	}
	return NULL;
}

static void ipcache4_purge(ip_cache4 **ipcache, time_t lifetime)
{
	ip_cache4 *elem, *tmp;
	time_t now = boottime();
	HASH_ITER(hh, *ipcache, elem, tmp)
	{
		if (now >= (elem->data.last + lifetime))
		{
			HASH_DEL(*ipcache, elem);
			ipcache_item_destroy(&elem->data);
			free(elem);
		}
	}
}
static void ipcache6_purge(ip_cache6 **ipcache, time_t lifetime)
{
	ip_cache6 *elem, *tmp;
	time_t now = boottime();
	HASH_ITER(hh, *ipcache, elem, tmp)
	{
		if (now >= (elem->data.last + lifetime))
		{
			HASH_DEL(*ipcache, elem);
			ipcache_item_destroy(&elem->data);
			free(elem);
		}
	}
}
static void ipcache_purge(ip_cache *ipcache, time_t lifetime)
{
	if (lifetime) // 0 = no expire
	{
		ipcache4_purge(&ipcache->ipcache4, lifetime);
		ipcache6_purge(&ipcache->ipcache6, lifetime);
	}
}
static time_t ipcache_purge_prev=0;
void ipcachePurgeRateLimited(ip_cache *ipcache, time_t lifetime)
{
	time_t now = boottime();
	// do not purge too often to save resources
	if (ipcache_purge_prev != now)
	{
		ipcache_purge(ipcache, lifetime);
		ipcache_purge_prev = now;
	}
}

