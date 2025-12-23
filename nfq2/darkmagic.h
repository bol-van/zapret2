#pragma once

#include "nfqws.h"
#include "checksum.h"
#include "packet_queue.h"
#include "pools.h"

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>

#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND           78
#endif

#ifdef __CYGWIN__
#define INITGUID
#include "windivert/windivert.h"
#endif

#ifndef IPPROTO_DIVERT
#define IPPROTO_DIVERT 258
#endif

#ifndef AF_DIVERT
#define	AF_DIVERT	44	/* divert(4) */
#endif
#ifndef PF_DIVERT
#define PF_DIVERT AF_DIVERT
#endif

#define TCP_KIND_END 		0
#define TCP_KIND_NOOP 		1
#define TCP_KIND_MSS 		2
#define TCP_KIND_SCALE 		3
#define TCP_KIND_SACK_PERM	4
#define TCP_KIND_SACK		5
#define TCP_KIND_TS		8
#define TCP_KIND_MD5		19
#define TCP_KIND_AO		29
#define TCP_KIND_FASTOPEN	34

#ifndef IPPROTO_MH
#define IPPROTO_MH		135
#endif
#ifndef IPPROTO_HIP
#define IPPROTO_HIP		139
#endif
#ifndef IPPROTO_SHIM6
#define IPPROTO_SHIM6		140
#endif

// returns netorder value
uint32_t net32_add(uint32_t netorder_value, uint32_t cpuorder_increment);
uint32_t net16_add(uint16_t netorder_value, uint16_t cpuorder_increment);

#define SCALE_NONE ((uint8_t)-1)

#define VERDICT_PASS		0
#define VERDICT_MODIFY		1
#define VERDICT_DROP		2
#define VERDICT_MASK		3
#define VERDICT_NOCSUM		4
#define VERDICT_MASK_VALID	7

#define IP4_TOS(ip_header) (ip_header ? ip_header->ip_tos : 0)
#define IP4_IP_ID(ip_header) (ip_header ? ip_header->ip_id : 0)
#define IP6_FLOW(ip6_header) (ip6_header ? ip6_header->ip6_ctlun.ip6_un1.ip6_un1_flow : 0)
	
void extract_ports(const struct tcphdr *tcphdr, const struct udphdr *udphdr, uint8_t *proto, uint16_t *sport, uint16_t *dport);
void extract_endpoints(const struct ip *ip,const struct ip6_hdr *ip6hdr,const struct tcphdr *tcphdr,const struct udphdr *udphdr, struct sockaddr_storage *src, struct sockaddr_storage *dst);
bool extract_dst(const uint8_t *data, size_t len, struct sockaddr* dst);
uint8_t *tcp_find_option(struct tcphdr *tcp, uint8_t kind);
uint32_t *tcp_find_timestamps(struct tcphdr *tcp);
uint8_t tcp_find_scale_factor(const struct tcphdr *tcp);
uint16_t tcp_find_mss(const struct tcphdr *tcp);
bool tcp_synack_segment(const struct tcphdr *tcphdr);
bool tcp_syn_segment(const struct tcphdr *tcphdr);

bool ip_has_df(const struct ip *ip);


bool make_writeable_dir();
bool ensure_file_access(const char *filename);
#ifdef __CYGWIN__
extern uint32_t w_win32_error;

bool ensure_dir_access(const char *filename);
bool prepare_low_appdata();
bool win_sandbox(void);
bool win_dark_init(const struct str_list_head *ssid_filter, const struct str_list_head *nlm_filter);
bool win_dark_deinit(void);
bool logical_net_filter_present(void);
bool logical_net_filter_match(void);
bool nlm_list(bool bAll);
bool windivert_init(const char *filter);
bool windivert_recv(uint8_t *packet, size_t *len, WINDIVERT_ADDRESS *wa);
bool windivert_send(const uint8_t *packet, size_t len, const WINDIVERT_ADDRESS *wa);
#else
#define ensure_dir_access(dir) ensure_file_access(dir)
// should pre-do it if dropping privileges. otherwise its not necessary
bool rawsend_preinit(bool bind_fix4, bool bind_fix6);
#endif

// auto creates internal socket and uses it for subsequent calls
bool rawsend(const struct sockaddr* dst,uint32_t fwmark,const char *ifout,const void *data,size_t len);
bool rawsend_rp(const struct rawpacket *rp);
// return trues if all packets were send successfully
bool rawsend_queue(struct rawpacket_tailhead *q);
// cleans up socket autocreated by rawsend
void rawsend_cleanup(void);
bool rawsend_rep(int repeats, const struct sockaddr* dst, uint32_t fwmark, const char *ifout, const void *data, size_t len);

#ifdef BSD
int socket_divert(sa_family_t family);
#endif

const char *proto_name(uint8_t proto);
uint16_t family_from_proto(uint8_t l3proto);
void print_ip(const struct ip *ip);
void print_ip6hdr(const struct ip6_hdr *ip6hdr, uint8_t proto);
void print_tcphdr(const struct tcphdr *tcphdr);
void print_udphdr(const struct udphdr *udphdr);
void str_ip(char *s, size_t s_len, const struct ip *ip);
void str_ip6hdr(char *s, size_t s_len, const struct ip6_hdr *ip6hdr, uint8_t proto);
void str_srcdst_ip6(char *s, size_t s_len, const void *saddr,const void *daddr);
void str_tcphdr(char *s, size_t s_len, const struct tcphdr *tcphdr);
void str_udphdr(char *s, size_t s_len, const struct udphdr *udphdr);

bool proto_check_ipv4(const uint8_t *data, size_t len);
void proto_skip_ipv4(const uint8_t **data, size_t *len);
bool proto_check_ipv6(const uint8_t *data, size_t len);
void proto_skip_ipv6(const uint8_t **data, size_t *len, uint8_t *proto_type, const uint8_t **last_header_type);
bool proto_set_last_ip6_proto(struct ip6_hdr *ip6, size_t len, uint8_t proto);
uint8_t *proto_find_ip6_exthdr(struct ip6_hdr *ip6, size_t len, uint8_t proto);
bool proto_check_tcp(const uint8_t *data, size_t len);
void proto_skip_tcp(const uint8_t **data, size_t *len);
bool proto_check_udp(const uint8_t *data, size_t len);
void proto_skip_udp(const uint8_t **data, size_t *len);
struct dissect
{
	const uint8_t *data_pkt;
	size_t len_pkt;
	const struct ip *ip;
	const struct ip6_hdr *ip6;
	size_t len_l3;
	uint8_t proto;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	size_t len_l4;
	size_t transport_len;
	const uint8_t *data_payload;
	size_t len_payload;
};
void proto_dissect_l3l4(const uint8_t *data, size_t len, struct dissect *dis);
void reverse_ip(struct ip *ip, struct ip6_hdr *ip6);
void reverse_tcp(struct tcphdr *tcp);

uint8_t ttl46(const struct ip *ip, const struct ip6_hdr *ip6);

void verdict_tcp_csum_fix(uint8_t verdict, struct tcphdr *tcphdr, size_t transport_len, const struct ip *ip, const struct ip6_hdr *ip6hdr);
void verdict_udp_csum_fix(uint8_t verdict, struct udphdr *udphdr, size_t transport_len, const struct ip *ip, const struct ip6_hdr *ip6hdr);

void dbgprint_socket_buffers(int fd);
bool set_socket_buffers(int fd, int rcvbuf, int sndbuf);


#ifdef HAS_FILTER_SSID

struct wlan_interface
{
	int ifindex;
	char ifname[IFNAMSIZ], ssid[33];
};
#define WLAN_INTERFACE_MAX 16
struct wlan_interface_collection
{
	int count;
	struct wlan_interface wlan[WLAN_INTERFACE_MAX];
};

extern struct wlan_interface_collection wlans;

void wlan_info_deinit(void);
bool wlan_info_init(void);
bool wlan_info_get_rate_limited(void);
const char *wlan_ssid_search_ifname(const char *ifname);
const char *wlan_ssid_search_ifidx(int ifidx);

#endif
