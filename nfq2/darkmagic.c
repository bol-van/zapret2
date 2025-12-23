#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>

#ifndef IP_NODEFRAG
// for very old toolchains
#define IP_NODEFRAG     22
#endif

#include "darkmagic.h"
#include "helpers.h"
#include "params.h"
#include "nfqws.h"

#ifdef __CYGWIN__
#include <sys/cygwin.h>

#include <wlanapi.h>
#include <netlistmgr.h>
#include <aclapi.h>
#include <wchar.h>
#include <KnownFolders.h>
#include <shlobj.h>

#ifndef ERROR_INVALID_IMAGE_HASH
#define ERROR_INVALID_IMAGE_HASH __MSABI_LONG(577)
#endif

#endif

#ifdef __linux__
#include <linux/nl80211.h>
#include <linux/genetlink.h>
#include <libmnl/libmnl.h>
#include <net/if.h>
#endif

uint32_t net32_add(uint32_t netorder_value, uint32_t cpuorder_increment)
{
	return htonl(ntohl(netorder_value)+cpuorder_increment);
}
uint32_t net16_add(uint16_t netorder_value, uint16_t cpuorder_increment)
{
	return htons(ntohs(netorder_value)+cpuorder_increment);
}

bool ip_has_df(const struct ip *ip)
{
	return ip && !!(ntohs(ip->ip_off) & IP_DF);
}

uint8_t *tcp_find_option(struct tcphdr *tcp, uint8_t kind)
{
	uint8_t *t = (uint8_t*)(tcp+1);
	uint8_t *end = (uint8_t*)tcp + (tcp->th_off<<2);
	while(t<end)
	{
		switch(*t)
		{
			case TCP_KIND_END:
				return NULL;
			case TCP_KIND_NOOP:
				t++;
				break;
			default: // kind,len,data
				if ((t+1)>=end || t[1]<2 || (t+t[1])>end)
					return NULL;
				if (*t==kind)
					return t;
				t+=t[1];
				break;
		}
	}
	return NULL;
}
uint32_t *tcp_find_timestamps(struct tcphdr *tcp)
{
	uint8_t *t = tcp_find_option(tcp, TCP_KIND_TS);
	return (t && t[1]==10) ? (uint32_t*)(t+2) : NULL;
}
uint8_t tcp_find_scale_factor(const struct tcphdr *tcp)
{
	uint8_t *scale = tcp_find_option((struct tcphdr*)tcp, TCP_KIND_SCALE);
	if (scale && scale[1]==3) return scale[2];
	return SCALE_NONE;
}
uint16_t tcp_find_mss(const struct tcphdr *tcp)
{
	uint8_t *t = tcp_find_option((struct tcphdr *)tcp, TCP_KIND_MSS);
	return (t && t[1]==4) ? *(uint16_t*)(t+2) : 0;
}
bool tcp_synack_segment(const struct tcphdr *tcphdr)
{
	/* check for set bits in TCP hdr */
	return ((tcphdr->th_flags & (TH_URG|TH_ACK|TH_PUSH|TH_RST|TH_SYN|TH_FIN)) == (TH_ACK|TH_SYN));
}
bool tcp_syn_segment(const struct tcphdr *tcphdr)
{
	/* check for set bits in TCP hdr */
	return ((tcphdr->th_flags & (TH_URG|TH_ACK|TH_PUSH|TH_RST|TH_SYN|TH_FIN)) == TH_SYN);
}


void extract_ports(const struct tcphdr *tcphdr, const struct udphdr *udphdr, uint8_t *proto, uint16_t *sport, uint16_t *dport)
{
	if (sport) *sport  = htons(tcphdr ? tcphdr->th_sport : udphdr ? udphdr->uh_sport : 0);
	if (dport) *dport  = htons(tcphdr ? tcphdr->th_dport : udphdr ? udphdr->uh_dport : 0);
	if (proto) *proto = tcphdr ? IPPROTO_TCP : udphdr ? IPPROTO_UDP : -1;
}

bool extract_dst(const uint8_t *data, size_t len, struct sockaddr* dst)
{
	if (proto_check_ipv4(data,len))
	{
		struct sockaddr_in *in = (struct sockaddr_in *)dst;
		in->sin_family = AF_INET;
		in->sin_port = 0;
		in->sin_addr = ((struct ip*)data)->ip_dst;
	}
	else if (proto_check_ipv6(data,len))
	{
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)dst;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = 0;
		in6->sin6_flowinfo = 0;
		in6->sin6_scope_id = 0;
		in6->sin6_addr = ((struct ip6_hdr*)data)->ip6_dst;
	}
	else
		return false;
	return true;
}

void extract_endpoints(const struct ip *ip,const struct ip6_hdr *ip6hdr,const struct tcphdr *tcphdr,const struct udphdr *udphdr, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
	if (ip)
	{
		struct sockaddr_in *si;

		if (dst)
		{
			si = (struct sockaddr_in*)dst;
			si->sin_family = AF_INET;
			si->sin_port = tcphdr ? tcphdr->th_dport : udphdr ? udphdr->uh_dport : 0;
			si->sin_addr = ip->ip_dst;
		}

		if (src)
		{
			si = (struct sockaddr_in*)src;
			si->sin_family = AF_INET;
			si->sin_port = tcphdr ? tcphdr->th_sport : udphdr ? udphdr->uh_sport : 0;
			si->sin_addr = ip->ip_src;
		}
	}
	else if (ip6hdr)
	{
		struct sockaddr_in6 *si;

		if (dst)
		{
			si = (struct sockaddr_in6*)dst;
			si->sin6_family = AF_INET6;
			si->sin6_port = tcphdr ? tcphdr->th_dport : udphdr ? udphdr->uh_dport : 0;
			si->sin6_addr = ip6hdr->ip6_dst;
			si->sin6_flowinfo = 0;
			si->sin6_scope_id = 0;
		}

		if (src)
		{
			si = (struct sockaddr_in6*)src;
			si->sin6_family = AF_INET6;
			si->sin6_port = tcphdr ? tcphdr->th_sport : udphdr ? udphdr->uh_sport : 0;
			si->sin6_addr = ip6hdr->ip6_src;
			si->sin6_flowinfo = 0;
			si->sin6_scope_id = 0;
		}
	}
}

const char *proto_name(uint8_t proto)
{
	switch(proto)
	{
		case IPPROTO_TCP:
			return "tcp";
		case IPPROTO_UDP:
			return "udp";
		case IPPROTO_ICMP:
			return "icmp";
		case IPPROTO_ICMPV6:
			return "icmp6";
		case IPPROTO_IGMP:
			return "igmp";
		case IPPROTO_ESP:
			return "esp";
		case IPPROTO_AH:
			return "ah";
		case IPPROTO_IPV6:
			return "6in4";
		case IPPROTO_IPIP:
			return "4in4";
#ifdef IPPROTO_GRE
		case IPPROTO_GRE:
			return "gre";
#endif
#ifdef IPPROTO_SCTP
		case IPPROTO_SCTP:
			return "sctp";
#endif
		default:
			return NULL;
	}
}
static void str_proto_name(char *s, size_t s_len, uint8_t proto)
{
	const char *name = proto_name(proto);
	if (name)
		snprintf(s,s_len,"%s",name);
	else
		snprintf(s,s_len,"%u",proto);
}
uint16_t family_from_proto(uint8_t l3proto)
{
	switch(l3proto)
	{
		case IPPROTO_IP: return AF_INET;
		case IPPROTO_IPV6: return AF_INET6;
		default: return -1;
	}
}

static void str_srcdst_ip(char *s, size_t s_len, const void *saddr,const void *daddr)
{
	char s_ip[16],d_ip[16];
	*s_ip=*d_ip=0;
	inet_ntop(AF_INET, saddr, s_ip, sizeof(s_ip));
	inet_ntop(AF_INET, daddr, d_ip, sizeof(d_ip));
	snprintf(s,s_len,"%s => %s",s_ip,d_ip);
}
void str_ip(char *s, size_t s_len, const struct ip *ip)
{
	char ss[35],s_proto[16];
	str_srcdst_ip(ss,sizeof(ss),&ip->ip_src,&ip->ip_dst);
	str_proto_name(s_proto,sizeof(s_proto),ip->ip_p);
	snprintf(s,s_len,"%s proto=%s ttl=%u",ss,s_proto,ip->ip_ttl);
}
void print_ip(const struct ip *ip)
{
	char s[66];
	str_ip(s,sizeof(s),ip);
	printf("%s",s);
}
void str_srcdst_ip6(char *s, size_t s_len, const void *saddr,const void *daddr)
{
	char s_ip[40],d_ip[40];
	*s_ip=*d_ip=0;
	inet_ntop(AF_INET6, saddr, s_ip, sizeof(s_ip));
	inet_ntop(AF_INET6, daddr, d_ip, sizeof(d_ip));
	snprintf(s,s_len,"%s => %s",s_ip,d_ip);
}
void str_ip6hdr(char *s, size_t s_len, const struct ip6_hdr *ip6hdr, uint8_t proto)
{
	char ss[83],s_proto[16];
	str_srcdst_ip6(ss,sizeof(ss),&ip6hdr->ip6_src,&ip6hdr->ip6_dst);
	str_proto_name(s_proto,sizeof(s_proto),proto);
	snprintf(s,s_len,"%s proto=%s ttl=%u",ss,s_proto,ip6hdr->ip6_hlim);
}
void print_ip6hdr(const struct ip6_hdr *ip6hdr, uint8_t proto)
{
	char s[128];
	str_ip6hdr(s,sizeof(s),ip6hdr,proto);
	printf("%s",s);
}
void str_tcphdr(char *s, size_t s_len, const struct tcphdr *tcphdr)
{
	char flags[7],*f=flags;
	if (tcphdr->th_flags & TH_SYN) *f++='S';
	if (tcphdr->th_flags & TH_ACK) *f++='A';
	if (tcphdr->th_flags & TH_RST) *f++='R';
	if (tcphdr->th_flags & TH_FIN) *f++='F';
	if (tcphdr->th_flags & TH_PUSH) *f++='P';
	if (tcphdr->th_flags & TH_URG) *f++='U';
	*f=0;
	snprintf(s,s_len,"sport=%u dport=%u flags=%s seq=%u ack_seq=%u",htons(tcphdr->th_sport),htons(tcphdr->th_dport),flags,htonl(tcphdr->th_seq),htonl(tcphdr->th_ack));
}
void print_tcphdr(const struct tcphdr *tcphdr)
{
	char s[80];
	str_tcphdr(s,sizeof(s),tcphdr);
	printf("%s",s);
}
void str_udphdr(char *s, size_t s_len, const struct udphdr *udphdr)
{
	snprintf(s,s_len,"sport=%u dport=%u",htons(udphdr->uh_sport),htons(udphdr->uh_dport));
}
void print_udphdr(const struct udphdr *udphdr)
{
	char s[30];
	str_udphdr(s,sizeof(s),udphdr);
	printf("%s",s);
}




bool proto_check_ipv4(const uint8_t *data, size_t len)
{
	return 	len >= sizeof(struct ip) && (data[0] & 0xF0) == 0x40 &&
		len >= ((data[0] & 0x0F) << 2);
}
// move to transport protocol
void proto_skip_ipv4(const uint8_t **data, size_t *len)
{
	size_t l;

	l = (**data & 0x0F) << 2;
	*data += l;
	*len -= l;
}
bool proto_check_tcp(const uint8_t *data, size_t len)
{
	return len >= sizeof(struct tcphdr) && len >= ((data[12] & 0xF0) >> 2);
}
void proto_skip_tcp(const uint8_t **data, size_t *len)
{
	size_t l;
	l = ((*data)[12] & 0xF0) >> 2;
	*data += l;
	*len -= l;
}
bool proto_check_udp(const uint8_t *data, size_t len)
{
	return len >= sizeof(struct udphdr) && len>=(data[4]<<8 | data[5]);
}
void proto_skip_udp(const uint8_t **data, size_t *len)
{
	*data += 8;
	*len -= 8;
}

bool proto_check_ipv6(const uint8_t *data, size_t len)
{
	return 	len >= sizeof(struct ip6_hdr) && (data[0] & 0xF0) == 0x60 &&
		(len - sizeof(struct ip6_hdr)) >= ntohs(((struct ip6_hdr*)data)->ip6_ctlun.ip6_un1.ip6_un1_plen);
}
// move to transport protocol
// proto_type = 0 => error
void proto_skip_ipv6(const uint8_t **data, size_t *len, uint8_t *proto_type, const uint8_t **last_header_type)
{
	size_t hdrlen;
	uint8_t HeaderType;

	if (proto_type) *proto_type = 0; // put error in advance

	HeaderType = (*data)[6]; // NextHeader field
	if (last_header_type) *last_header_type = (*data)+6;
	*data += sizeof(struct ip6_hdr); *len -= sizeof(struct ip6_hdr); // skip ipv6 base header
	while (*len) // need at least one byte for NextHeader field
	{
		switch (HeaderType)
		{
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		case IPPROTO_MH: // mobility header
		case IPPROTO_HIP: // Host Identity Protocol Version v2
		case IPPROTO_SHIM6:
			if (*len < 2) return; // error
			hdrlen = 8 + ((*data)[1] << 3);
			break;
		case IPPROTO_FRAGMENT: // fragment. length fixed to 8, hdrlen field defined as reserved
			hdrlen = 8;
			break;
		case IPPROTO_AH:
			// special case. length in ah header is in 32-bit words minus 2
			if (*len < 2) return; // error
			hdrlen = 8 + ((*data)[1] << 2);
			break;
		case IPPROTO_NONE: // no next header
			return; // error
		default:
			// we found some meaningful payload. it can be tcp, udp, icmp or some another exotic shit
			if (proto_type) *proto_type = HeaderType;
			return;
		}
		if (*len < hdrlen) return; // error
		HeaderType = **data;
		if (last_header_type) *last_header_type = *data;
		// advance to the next header location
		*len -= hdrlen;
		*data += hdrlen;
	}
	// we have garbage
}

bool proto_set_last_ip6_proto(struct ip6_hdr *ip6, size_t len, uint8_t proto)
{
	size_t hdrlen;
	uint8_t HeaderType, *pproto, *data;

	if (len<sizeof(struct ip6_hdr)) return false;

	pproto = &ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	data = (uint8_t*)(ip6+1);
	len -= sizeof(struct ip6_hdr);
	while (len) // need at least one byte for NextHeader field
	{
		switch (*pproto)
		{
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		case IPPROTO_MH: // mobility header
		case IPPROTO_HIP: // Host Identity Protocol Version v2
		case IPPROTO_SHIM6:
			if (len < 2) return false; // error
			hdrlen = 8 + (data[1] << 3);
			break;
		case IPPROTO_FRAGMENT: // fragment. length fixed to 8, hdrlen field defined as reserved
			hdrlen = 8;
			break;
		case IPPROTO_AH:
			// special case. length in ah header is in 32-bit words minus 2
			if (len < 2) return false; // error
			hdrlen = 8 + (data[1] << 2);
			break;
		default:
			// we found some meaningful payload. it can be tcp, udp, icmp or some another exotic shit
			*pproto = proto;
			return true;
		}
		if (len < hdrlen) return false; // error
		pproto = data;
		len -= hdrlen; data += hdrlen;
	}
	*pproto = proto;
	return true;
}

uint8_t *proto_find_ip6_exthdr(struct ip6_hdr *ip6, size_t len, uint8_t proto)
{
	size_t hdrlen;
	uint8_t HeaderType, last_proto, *data;

	if (len<sizeof(struct ip6_hdr)) return false;

	last_proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	data = (uint8_t*)(ip6+1);
	len -= sizeof(struct ip6_hdr);
	while (len) // need at least one byte for NextHeader field
	{
		if (last_proto==proto) return data; // found
		switch (last_proto)
		{
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		case IPPROTO_MH: // mobility header
		case IPPROTO_HIP: // Host Identity Protocol Version v2
		case IPPROTO_SHIM6:
			if (len < 2) return false; // error
			hdrlen = 8 + (data[1] << 3);
			break;
		case IPPROTO_FRAGMENT: // fragment. length fixed to 8, hdrlen field defined as reserved
			hdrlen = 8;
			break;
		case IPPROTO_AH:
			// special case. length in ah header is in 32-bit words minus 2
			if (len < 2) return false; // error
			hdrlen = 8 + (data[1] << 2);
			break;
		default:
			// we found some meaningful payload. it can be tcp, udp, icmp or some another exotic shit
			// exthdr was not found
			return NULL;
		}
		if (len < hdrlen) return false; // error
		last_proto = *data;
		len -= hdrlen; data += hdrlen;
	}
	// exthdr was not found
	return NULL;
}

void proto_dissect_l3l4(const uint8_t *data, size_t len, struct dissect *dis)
{
	const uint8_t *p;

	memset(dis,0,sizeof(*dis));

	dis->data_pkt = data;
	dis->len_pkt = len;

	if (proto_check_ipv4(data, len))
	{
		dis->ip = (const struct ip *) data;
		dis->proto = dis->ip->ip_p;
		p = data;
		proto_skip_ipv4(&data, &len);
		dis->len_l3 = data-p;
	}
	else if (proto_check_ipv6(data, len))
	{
		dis->ip6 = (const struct ip6_hdr *) data;
		p = data;
		proto_skip_ipv6(&data, &len, &dis->proto, NULL);
		dis->len_l3 = data-p;
	}
	else
	{
		return;
	}

	if (dis->proto==IPPROTO_TCP && proto_check_tcp(data, len))
	{
		dis->tcp = (const struct tcphdr *) data;
		dis->transport_len = len;

		p = data;
		proto_skip_tcp(&data, &len);
		dis->len_l4 = data-p;

		dis->data_payload = data;
		dis->len_payload = len;

	}
	else if (dis->proto==IPPROTO_UDP && proto_check_udp(data, len))
	{
		dis->udp = (const struct udphdr *) data;
		dis->transport_len = len;

		p = data;
		proto_skip_udp(&data, &len);
		dis->len_l4 = data-p;

		dis->data_payload = data;
		dis->len_payload = len;
	}
}

void reverse_ip(struct ip *ip, struct ip6_hdr *ip6)
{
	if (ip)
	{
		struct in_addr temp = ip->ip_src;
		ip->ip_src = ip->ip_dst;
		ip->ip_dst = temp;
		ip4_fix_checksum(ip);
	}
	if (ip6)
	{
		struct in6_addr temp = ip6->ip6_src;
		ip6->ip6_src = ip6->ip6_dst;
		ip6->ip6_dst = temp;
	}
}
void reverse_tcp(struct tcphdr *tcp)
{
	uint16_t tport = tcp->th_sport;
	tcp->th_sport = tcp->th_dport;
	tcp->th_dport = tport;

	uint32_t tseq = tcp->th_seq;
	tcp->th_seq = tcp->th_ack;
	tcp->th_ack = tseq;
}


uint8_t ttl46(const struct ip *ip, const struct ip6_hdr *ip6)
{
	return ip ? ip->ip_ttl : ip6 ? ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim : 0;
}




#ifdef __CYGWIN__

uint32_t w_win32_error=0;

static BOOL RemoveTokenPrivs(void)
{
	BOOL bRes = FALSE;
	HANDLE hToken;
	TOKEN_PRIVILEGES *privs;
	DWORD k, dwSize;
	LUID luid_SeChangeNotifyPrivilege;

	if (LookupPrivilegeValue(NULL, SE_CHANGE_NOTIFY_NAME, &luid_SeChangeNotifyPrivilege))
	{
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				if (privs = (PTOKEN_PRIVILEGES)malloc(dwSize))
				{
					if (GetTokenInformation(hToken, TokenPrivileges, privs, dwSize, &dwSize))
					{
						for (k = 0; k < privs->PrivilegeCount; k++)
						{
							if (memcmp(&privs->Privileges[k].Luid, &luid_SeChangeNotifyPrivilege, sizeof(LUID)))
								privs->Privileges[k].Attributes = SE_PRIVILEGE_REMOVED;
						}
					}
					bRes = AdjustTokenPrivileges(hToken, FALSE, privs, dwSize, NULL, NULL);
					free(privs);
				}
			}
			CloseHandle(hToken);
		}
	}
	if (!bRes) w_win32_error = GetLastError();
	return bRes;
}

static SID_IDENTIFIER_AUTHORITY label_authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
BOOL LowMandatoryLevel(void)
{
	BOOL bRes = FALSE;
	HANDLE hToken;
	char buf1[32];
	TOKEN_MANDATORY_LABEL label_low;

	label_low.Label.Sid = (PSID)buf1;
	InitializeSid(label_low.Label.Sid, &label_authority, 1);
	label_low.Label.Attributes = 0;
	*GetSidSubAuthority(label_low.Label.Sid, 0) = SECURITY_MANDATORY_LOW_RID;

	// S-1-16-12288 : Mandatory Label\High Mandatory Level
	// S-1-16-8192  : Mandatory Label\Medium Mandatory Level
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &hToken))
	{
		bRes = SetTokenInformation(hToken, TokenIntegrityLevel, &label_low, sizeof(label_low));
		CloseHandle(hToken);
	}
	if (!bRes) w_win32_error = GetLastError();
	return bRes;
}

BOOL SetMandatoryLabelFile(LPCSTR lpFileName, DWORD dwMandatoryLabelRID, DWORD dwAceFlags)
{
	BOOL bRes=FALSE;
	DWORD dwErr, dwFileAttributes;
	char buf_label[16], buf_pacl[32];
	PSID label = (PSID)buf_label;
	PACL pacl = (PACL)buf_pacl;
	LPWSTR lpFileNameW = NULL;
	size_t szFileName;

	szFileName = strlen(lpFileName);
	if (!(lpFileNameW = (LPWSTR)LocalAlloc(LMEM_FIXED,(szFileName+1)*sizeof(WCHAR))))
		goto err;

	if (!MultiByteToWideChar(CP_UTF8, 0, lpFileName, -1, lpFileNameW, szFileName+1))
		goto err;

	if (!strncmp(lpFileName,"\\\\.\\",4))
		dwFileAttributes = 0;
	else
	{
		dwFileAttributes = GetFileAttributesW(lpFileNameW);
		if (dwFileAttributes == INVALID_FILE_ATTRIBUTES) goto err;
	}
	InitializeSid(label, &label_authority, 1);
	*GetSidSubAuthority(label, 0) = dwMandatoryLabelRID;
	if (InitializeAcl(pacl, sizeof(buf_pacl), ACL_REVISION) && AddMandatoryAce(pacl, (dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? ACL_REVISION_DS : ACL_REVISION, dwAceFlags, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, label))
	{
		dwErr = SetNamedSecurityInfoW(lpFileNameW, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pacl);
		SetLastError(dwErr);
		bRes = dwErr==ERROR_SUCCESS;
	}
err:
	if (!bRes) w_win32_error = GetLastError();
	LocalFree(lpFileNameW);
	return bRes;
}

BOOL SetMandatoryLabelFileW(LPCWSTR lpFileNameW, DWORD dwMandatoryLabelRID, DWORD dwAceFlags)
{
	BOOL bRes=FALSE;
	DWORD dwErr, dwFileAttributes;
	char buf_label[16], buf_pacl[32];
	PSID label = (PSID)buf_label;
	PACL pacl = (PACL)buf_pacl;

	if (!wcsncmp(lpFileNameW,L"\\\\.\\",4))
		dwFileAttributes = 0;
	else
	{
		dwFileAttributes = GetFileAttributesW(lpFileNameW);
		if (dwFileAttributes == INVALID_FILE_ATTRIBUTES) goto err;
	}

	InitializeSid(label, &label_authority, 1);
	*GetSidSubAuthority(label, 0) = dwMandatoryLabelRID;
	if (InitializeAcl(pacl, sizeof(buf_pacl), ACL_REVISION) && AddMandatoryAce(pacl, (dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? ACL_REVISION_DS : ACL_REVISION, dwAceFlags, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, label))
	{
		dwErr = SetNamedSecurityInfoW((LPWSTR)lpFileNameW, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pacl);
		SetLastError(dwErr);
		bRes = dwErr==ERROR_SUCCESS;
	}
err:
	if (!bRes) w_win32_error = GetLastError();
	return bRes;
}

bool ensure_file_access(const char *filename)
{
	return SetMandatoryLabelFile(filename, SECURITY_MANDATORY_LOW_RID, 0);
}
bool ensure_dir_access(const char *dir)
{
	return SetMandatoryLabelFile(dir, SECURITY_MANDATORY_LOW_RID, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
}

bool prepare_low_appdata()
{
	bool b = false;
	PWSTR pszPath = NULL;
	HRESULT hr = SHGetKnownFolderPath(&FOLDERID_LocalAppDataLow, 0, NULL, &pszPath);
	if (SUCCEEDED(hr))
	{
		size_t l = cygwin_conv_path(CCP_WIN_W_TO_POSIX | CCP_ABSOLUTE, pszPath, NULL, 0);
		char *buf = (char*)malloc(l+8);
		if (buf)
		{
			if (!cygwin_conv_path(CCP_WIN_W_TO_POSIX | CCP_ABSOLUTE, pszPath, buf, l))
			{
				b = true;
				setenv("APPDATALOW", buf, 1);
			}
			free(buf);
		}
		CoTaskMemFree(pszPath);
	}
	return b;
}

BOOL JobSandbox()
{
	BOOL bRes = FALSE;
	HANDLE hJob;
	JOBOBJECT_BASIC_LIMIT_INFORMATION basic_limit;
	JOBOBJECT_BASIC_UI_RESTRICTIONS basic_ui;

	if (hJob = CreateJobObjectW(NULL, NULL))
	{
		basic_limit.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
		// prevent child process creation
		basic_limit.ActiveProcessLimit = 1;
		// prevent some UI interaction and settings change
		basic_ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS | JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
		bRes = SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basic_limit, sizeof(basic_limit)) &&
			SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &basic_ui, sizeof(basic_ui)) &&
			AssignProcessToJobObject(hJob, GetCurrentProcess());
		w_win32_error = GetLastError();
		CloseHandle(hJob);
	}
	return bRes;
}


#define WINDIVERT_DEVICE_NAME "WinDivert"
static bool b_sandbox_set = false;
bool win_sandbox(void)
{
	// there's no way to return privs
	if (!b_sandbox_set)
	{
		if (!RemoveTokenPrivs())
			return FALSE;

		// set low mandatory label on windivert device to allow administrators with low label access the driver
		if (logical_net_filter_present() && !SetMandatoryLabelFile("\\\\.\\" WINDIVERT_DEVICE_NAME, SECURITY_MANDATORY_LOW_RID, 0))
			return FALSE;
		if (!LowMandatoryLevel())
			return false;
		if (!JobSandbox())
			return false;
		b_sandbox_set = true;
	}
	return true;
}



static HANDLE w_filter = NULL;
static OVERLAPPED ovl = { .hEvent = NULL };
static const struct str_list_head *wlan_filter_ssid = NULL, *nlm_filter_net = NULL;
static DWORD logical_net_filter_tick=0;
INetworkListManager* pNetworkListManager=NULL;

static void guid2str(const GUID *guid, char *str)
{
	snprintf(str,37, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", guid->Data1, guid->Data2, guid->Data3, guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3], guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}
static bool str2guid(const char* str, GUID *guid)
{
	unsigned int u[11],k;

	if (36 != strlen(str) || 11 != sscanf(str, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", u+0, u+1, u+2, u+3, u+4, u+5, u+6, u+7, u+8, u+9, u+10))
		return false;
	guid->Data1 = u[0];
	if ((u[1] & 0xFFFF0000) || (u[2] & 0xFFFF0000)) return false;
	guid->Data2 = (USHORT)u[1];
	guid->Data3 = (USHORT)u[2];
	for (k = 0; k < 8; k++)
	{
		if (u[k+3] & 0xFFFFFF00) return false;
		guid->Data4[k] = (UCHAR)u[k+3];
	}
	return true;
}

static const char *sNetworkCards="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards";
// get adapter name from guid string
static bool AdapterID2Name(const GUID *guid,char *name,DWORD name_len)
{
	char sguid[39],sidx[32],val[256];
	HKEY hkNetworkCards,hkCard;
	DWORD dwIndex,dwLen;
	bool bRet = false;
	WCHAR namew[128];
	DWORD namew_len;

	if (name_len<2) return false;

	if ((w_win32_error = RegOpenKeyExA(HKEY_LOCAL_MACHINE,sNetworkCards,0,KEY_ENUMERATE_SUB_KEYS,&hkNetworkCards)) == ERROR_SUCCESS)
	{
		guid2str(guid, sguid+1);
		sguid[0]='{';
		sguid[37]='}';
		sguid[38]='\0';

		for (dwIndex=0;;dwIndex++)
		{
			dwLen=sizeof(sidx)-1;
			w_win32_error = RegEnumKeyExA(hkNetworkCards,dwIndex,sidx,&dwLen,NULL,NULL,NULL,NULL);
			if (w_win32_error == ERROR_SUCCESS)
			{
				sidx[dwLen]='\0';

				if ((w_win32_error = RegOpenKeyExA(hkNetworkCards,sidx,0,KEY_QUERY_VALUE,&hkCard)) == ERROR_SUCCESS)
				{
					dwLen=sizeof(val)-1;
					if ((w_win32_error = RegQueryValueExA(hkCard,"ServiceName",NULL,NULL,val,&dwLen)) == ERROR_SUCCESS)
					{
						val[dwLen]='\0';
						if (!strcmp(val,sguid))
						{
							namew_len = sizeof(namew)-sizeof(WCHAR);
							if ((w_win32_error = RegQueryValueExW(hkCard,L"Description",NULL,NULL,(LPBYTE)namew,&namew_len)) == ERROR_SUCCESS)
							{
								namew[namew_len/sizeof(WCHAR)]=L'\0';
								if (WideCharToMultiByte(CP_UTF8, 0, namew, -1, name, name_len, NULL, NULL))
									bRet = true;
							}
						}
					}
					RegCloseKey(hkCard);
				}
				if (bRet) break;
			}
			else
				break;
		}
		RegCloseKey(hkNetworkCards);
	}

	return bRet;
}

bool win_dark_init(const struct str_list_head *ssid_filter, const struct str_list_head *nlm_filter)
{
	win_dark_deinit();
	if (LIST_EMPTY(ssid_filter)) ssid_filter=NULL;
	if (LIST_EMPTY(nlm_filter)) nlm_filter=NULL;

	if (nlm_filter)
	{
		if (SUCCEEDED(w_win32_error = CoInitialize(NULL)))
		{
			if (FAILED(w_win32_error = CoCreateInstance(&CLSID_NetworkListManager, NULL, CLSCTX_ALL, &IID_INetworkListManager, (LPVOID*)&pNetworkListManager)))
			{
				CoUninitialize();
				return false;
			}
		}
		else
			return false;
	}
	nlm_filter_net = nlm_filter;
	wlan_filter_ssid = ssid_filter;
	return true;
}
bool win_dark_deinit(void)
{
	if (pNetworkListManager)
	{
		pNetworkListManager->lpVtbl->Release(pNetworkListManager);
		pNetworkListManager = NULL;
	}
	if (nlm_filter_net) CoUninitialize();
	wlan_filter_ssid = nlm_filter_net = NULL;
}


bool nlm_list(bool bAll)
{
	bool bRet = true;

	if (SUCCEEDED(w_win32_error = CoInitialize(NULL)))
	{
		INetworkListManager* pNetworkListManager;
		if (SUCCEEDED(w_win32_error = CoCreateInstance(&CLSID_NetworkListManager, NULL, CLSCTX_ALL, &IID_INetworkListManager, (LPVOID*)&pNetworkListManager)))
		{
			IEnumNetworks* pEnumNetworks;
			if (SUCCEEDED(w_win32_error = pNetworkListManager->lpVtbl->GetNetworks(pNetworkListManager, NLM_ENUM_NETWORK_ALL, &pEnumNetworks)))
			{
				INetwork *pNet;
				INetworkConnection *pConn;
				IEnumNetworkConnections *pEnumConnections;
				VARIANT_BOOL bIsConnected, bIsConnectedInet;
				NLM_NETWORK_CATEGORY category;
				GUID idNet, idAdapter;
				BSTR bstrName;
				char Name[128],Name2[128];
				int connected;
				for (connected = 1; connected >= !bAll; connected--)
				{
					for (;;)
					{
						if (FAILED(w_win32_error = pEnumNetworks->lpVtbl->Next(pEnumNetworks, 1, &pNet, NULL)))
						{
							bRet = false;
							break;
						}
						if (w_win32_error != S_OK) break;
						if (SUCCEEDED(w_win32_error = pNet->lpVtbl->get_IsConnected(pNet, &bIsConnected)) &&
							SUCCEEDED(w_win32_error = pNet->lpVtbl->get_IsConnectedToInternet(pNet, &bIsConnectedInet)) &&
							SUCCEEDED(w_win32_error = pNet->lpVtbl->GetNetworkId(pNet, &idNet)) &&
							SUCCEEDED(w_win32_error = pNet->lpVtbl->GetCategory(pNet, &category)) &&
							SUCCEEDED(w_win32_error = pNet->lpVtbl->GetName(pNet, &bstrName)))
						{
							if (!!bIsConnected == connected)
							{
								if (WideCharToMultiByte(CP_UTF8, 0, bstrName, -1, Name, sizeof(Name), NULL, NULL))
								{
									printf("Name    : %s", Name);
									if (bIsConnected) printf(" (connected)");
									if (bIsConnectedInet) printf(" (inet)");
									printf(" (%s)\n",
										category==NLM_NETWORK_CATEGORY_PUBLIC ? "public" :
										category==NLM_NETWORK_CATEGORY_PRIVATE ? "private" :
										category==NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED ? "domain" :
										"unknown");
									guid2str(&idNet, Name);
									printf("NetID   : %s\n", Name);	
									if (connected && SUCCEEDED(w_win32_error = pNet->lpVtbl->GetNetworkConnections(pNet, &pEnumConnections)))
									{
										while ((w_win32_error = pEnumConnections->lpVtbl->Next(pEnumConnections, 1, &pConn, NULL))==S_OK)
										{
											if (SUCCEEDED(w_win32_error = pConn->lpVtbl->GetAdapterId(pConn,&idAdapter)))
											{
												guid2str(&idAdapter, Name);
												if (AdapterID2Name(&idAdapter,Name2,sizeof(Name2)))
													printf("Adapter : %s (%s)\n", Name2, Name);
												else
													printf("Adapter : %s\n", Name);
											}
											pConn->lpVtbl->Release(pConn);
										}
										pEnumConnections->lpVtbl->Release(pEnumConnections);
									}
									printf("\n");
								}
								else
								{
									w_win32_error = HRESULT_FROM_WIN32(GetLastError());
									bRet = false;
								}
							}
							SysFreeString(bstrName);
						}
						else
							bRet = false;
						pNet->lpVtbl->Release(pNet);
						if (!bRet) break;
					}
					if (!bRet) break;
					pEnumNetworks->lpVtbl->Reset(pEnumNetworks);
				}
				pEnumNetworks->lpVtbl->Release(pEnumNetworks);
			}
			else
				bRet = false;
			pNetworkListManager->lpVtbl->Release(pNetworkListManager);
		}
		else
			bRet = false;
	}
	else
		bRet = false;

	CoUninitialize();
	return bRet;
}

static bool nlm_filter_match(const struct str_list_head *nlm_list)
{
	// no filter given. always matches.
	if (!nlm_list || LIST_EMPTY(nlm_list))
	{
		w_win32_error = 0;
		return true;
	}

	bool bRet = true, bMatch = false;
	IEnumNetworks* pEnum;

	if (SUCCEEDED(w_win32_error = pNetworkListManager->lpVtbl->GetNetworks(pNetworkListManager, NLM_ENUM_NETWORK_CONNECTED, &pEnum)))
	{
		INetwork* pNet;
		GUID idNet,g;
		BSTR bstrName;
		char Name[128];
		struct str_list *nlm;
		for (;;)
		{
			if (FAILED(w_win32_error = pEnum->lpVtbl->Next(pEnum, 1, &pNet, NULL)))
			{
				bRet = false;
				break;
			}
			if (w_win32_error != S_OK) break;
			if (SUCCEEDED(w_win32_error = pNet->lpVtbl->GetNetworkId(pNet, &idNet)) &&
				SUCCEEDED(w_win32_error = pNet->lpVtbl->GetName(pNet, &bstrName)))
			{
				if (WideCharToMultiByte(CP_UTF8, 0, bstrName, -1, Name, sizeof(Name), NULL, NULL))
				{
					LIST_FOREACH(nlm, nlm_list, next)
					{
						bMatch = !strcmp(Name,nlm->str) || str2guid(nlm->str,&g) && !memcmp(&idNet,&g,sizeof(GUID));
						if (bMatch) break;
					}
				}
				else
				{
					w_win32_error = HRESULT_FROM_WIN32(GetLastError());
					bRet = false;
				}
				SysFreeString(bstrName);
			}
			else
				bRet = false;
			pNet->lpVtbl->Release(pNet);
			if (!bRet || bMatch) break;
		}
		pEnum->lpVtbl->Release(pEnum);
	}
	else
		bRet = false;
	return bRet && bMatch;
}

static bool wlan_filter_match(const struct str_list_head *ssid_list)
{
	DWORD dwCurVersion;
	HANDLE hClient = NULL;
	PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
	PWLAN_INTERFACE_INFO pIfInfo;
	PWLAN_CONNECTION_ATTRIBUTES pConnectInfo;
	DWORD connectInfoSize, k;
	bool bRes;
	struct str_list *ssid;
	size_t len;

	// no filter given. always matches.
	if (!ssid_list || LIST_EMPTY(ssid_list))
	{
		w_win32_error = 0;
		return true;
	}

	w_win32_error = WlanOpenHandle(2, NULL, &dwCurVersion, &hClient);
	if (w_win32_error != ERROR_SUCCESS) goto fail;
	w_win32_error = WlanEnumInterfaces(hClient, NULL, &pIfList);
	if (w_win32_error != ERROR_SUCCESS) goto fail;
	for (k = 0; k < pIfList->dwNumberOfItems; k++)
	{
		pIfInfo = pIfList->InterfaceInfo + k;
		if (pIfInfo->isState == wlan_interface_state_connected)
		{
			w_win32_error = WlanQueryInterface(hClient,
				&pIfInfo->InterfaceGuid,
				wlan_intf_opcode_current_connection,
				NULL,
				&connectInfoSize,
				(PVOID *)&pConnectInfo,
				NULL);
			if (w_win32_error != ERROR_SUCCESS) goto fail;

//			printf("%s\n", pConnectInfo->wlanAssociationAttributes.dot11Ssid.ucSSID);

			LIST_FOREACH(ssid, ssid_list, next)
			{
				len = strlen(ssid->str);
				if (len==pConnectInfo->wlanAssociationAttributes.dot11Ssid.uSSIDLength && !memcmp(ssid->str,pConnectInfo->wlanAssociationAttributes.dot11Ssid.ucSSID,len))
				{	
					WlanFreeMemory(pConnectInfo);
					goto found;
				}
			}

			WlanFreeMemory(pConnectInfo);
		}
	}
	w_win32_error = 0;
fail:
	bRes = false;
ex:
	if (pIfList) WlanFreeMemory(pIfList);
	if (hClient) WlanCloseHandle(hClient, 0);
	return bRes;
found:
	w_win32_error = 0;
	bRes = true;
	goto ex;
}

bool logical_net_filter_match(void)
{
	return wlan_filter_match(wlan_filter_ssid) && nlm_filter_match(nlm_filter_net);
}

bool logical_net_filter_present(void)
{
	return (wlan_filter_ssid && !LIST_EMPTY(wlan_filter_ssid)) || (nlm_filter_net && !LIST_EMPTY(nlm_filter_net));
}



static bool logical_net_filter_match_rate_limited(void)
{
	DWORD dwTick = GetTickCount() / 1000;
	if (logical_net_filter_tick == dwTick) return true;
	logical_net_filter_tick = dwTick;
	return logical_net_filter_match();
}

static HANDLE windivert_init_filter(const char *filter, UINT64 flags)
{
	LPSTR errormessage = NULL;
	HANDLE h, hMutex;
	const char *mutex_name = "Global\\winws_windivert_mutex";

	// windivert driver start in windivert.dll has race conditions
	hMutex = CreateMutexA(NULL,TRUE,mutex_name);
	if (hMutex && GetLastError()==ERROR_ALREADY_EXISTS)
		WaitForSingleObject(hMutex,INFINITE);
	h = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);
	w_win32_error = GetLastError();

	if (hMutex)
	{
		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
		SetLastError(w_win32_error);
	}

	if (h != INVALID_HANDLE_VALUE) return h;

	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, w_win32_error, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPSTR)&errormessage, 0, NULL);
	DLOG_ERR("windivert: error opening filter: %s", errormessage);
	LocalFree(errormessage);
	if (w_win32_error == ERROR_INVALID_IMAGE_HASH)
		DLOG_ERR("windivert: try to disable secure boot and install OS patches\n");

	return NULL;
}
void rawsend_cleanup(void)
{
	if (w_filter)
	{
		CancelIoEx(w_filter,&ovl);
		WinDivertClose(w_filter);
		w_filter=NULL;
	}
	if (ovl.hEvent)
	{
		CloseHandle(ovl.hEvent);
		ovl.hEvent=NULL;
	}
}
bool windivert_init(const char *filter)
{
	rawsend_cleanup();
	w_filter = windivert_init_filter(filter, 0);
	if (w_filter)
	{
		ovl.hEvent = CreateEventW(NULL,FALSE,FALSE,NULL);
		if (!ovl.hEvent)
		{
			w_win32_error = GetLastError();
			rawsend_cleanup();
			return false;
		}
		return true;
	}
	return false;
}

static bool windivert_recv_filter(HANDLE hFilter, uint8_t *packet, size_t *len, WINDIVERT_ADDRESS *wa)
{
	UINT recv_len;
	DWORD err;
	DWORD rd;
	char c;

	if (bQuit)
	{
		errno=EINTR;
		return false;
	}
	if (!logical_net_filter_match_rate_limited())
	{
		errno=ENODEV;
		return false;
	}
	usleep(0);

	if (WinDivertRecvEx(hFilter, packet, *len, &recv_len, 0, wa, NULL, &ovl))
	{
		*len = recv_len;
		return true;
	}

	for(;;)
	{
		w_win32_error = GetLastError();

		switch(w_win32_error)
		{
			case ERROR_IO_PENDING:
				// make signals working
				while (WaitForSingleObject(ovl.hEvent,50)==WAIT_TIMEOUT)
				{
					if (bQuit)
					{
						errno=EINTR;
						return false;
					}
					if (!logical_net_filter_match_rate_limited())
					{
						errno=ENODEV;
						return false;
					}
					usleep(0);
				}
				if (!GetOverlappedResult(hFilter,&ovl,&rd,TRUE))
					continue;
				*len = rd;
				return true;
			case ERROR_INSUFFICIENT_BUFFER:
				errno = ENOBUFS;
				break;
			case ERROR_NO_DATA:
				errno = ESHUTDOWN;
				break;
			default:
				errno = EIO;
		}
		break;
	}
	return false;
}
bool windivert_recv(uint8_t *packet, size_t *len, WINDIVERT_ADDRESS *wa)
{
	return windivert_recv_filter(w_filter,packet,len,wa);
}

static bool windivert_send_filter(HANDLE hFilter, const uint8_t *packet, size_t len, const WINDIVERT_ADDRESS *wa)
{
	bool b = WinDivertSend(hFilter,packet,(UINT)len,NULL,wa);
	w_win32_error = GetLastError();
	return b;
}
bool windivert_send(const uint8_t *packet, size_t len, const WINDIVERT_ADDRESS *wa)
{
	return windivert_send_filter(w_filter,packet,len,wa);
}

bool rawsend(const struct sockaddr* dst,uint32_t fwmark,const char *ifout,const void *data,size_t len)
{
	WINDIVERT_ADDRESS wa;

	if (!ifout) return false;

	memset(&wa,0,sizeof(wa));
	// pseudo interface id IfIdx.SubIfIdx
	if (sscanf(ifout,"%u.%u",&wa.Network.IfIdx,&wa.Network.SubIfIdx)!=2)
	{
		errno = EINVAL;
		return false;
	}
	wa.Outbound=1;
	wa.IPChecksum=1;
	wa.TCPChecksum=1;
	wa.UDPChecksum=1;
	wa.IPv6 = (dst->sa_family==AF_INET6);
	if (!windivert_send(data,len,&wa))
	{
		DLOG_ERR("windivert send error. win32 code %u\n",w_win32_error);
		return false;
	}

	return true;
}

#else // *nix

bool ensure_file_access(const char *filename)
{
	return !chown(filename, params.uid, -1);
}

static int rawsend_sock4=-1, rawsend_sock6=-1;
static bool b_bind_fix4=false, b_bind_fix6=false;
static void rawsend_clean_sock(int *sock)
{
	if (sock && *sock!=-1)
	{
		close(*sock);
		*sock=-1;
	}
}
void rawsend_cleanup(void)
{
	rawsend_clean_sock(&rawsend_sock4);
	rawsend_clean_sock(&rawsend_sock6);
}
static int *rawsend_family_sock(sa_family_t family)
{
	switch(family)
	{
		case AF_INET: return &rawsend_sock4;
		case AF_INET6: return &rawsend_sock6;
		default: return NULL;
	}
}

#ifdef BSD
int socket_divert(sa_family_t family)
{
	int fd;
	
#ifdef __FreeBSD__
	// freebsd14+ way
	// don't want to use ifdefs with os version to make binaries compatible with all versions
	fd = socket(PF_DIVERT, SOCK_RAW, 0);
	if (fd==-1 && (errno==EPROTONOSUPPORT || errno==EAFNOSUPPORT || errno==EPFNOSUPPORT))
#endif
		// freebsd13- or openbsd way
		fd = socket(family, SOCK_RAW, IPPROTO_DIVERT);
	return fd;
}
static int rawsend_socket_divert(sa_family_t family)
{
	// HACK HACK HACK HACK HACK HACK HACK HACK
	// FreeBSD doesnt allow IP_HDRINCL for IPV6
	// OpenBSD doesnt allow rawsending tcp frames
	// we either have to go to the link layer (its hard, possible problems arise, compat testing, ...) or use some HACKING
	// from my point of view disabling direct ability to send ip frames is not security. its SHIT

	int fd = socket_divert(family);
	if (fd!=-1 && !set_socket_buffers(fd,4096,RAW_SNDBUF))
	{
		close(fd);
		return -1;
	}
	return fd;
}
static int rawsend_sendto_divert(sa_family_t family, int sock, const void *buf, size_t len)
{
	struct sockaddr_storage sa;
	socklen_t slen;

#ifdef __FreeBSD__
	// since FreeBSD 14 it requires hardcoded ipv4 values, although can also send ipv6 frames
	family = AF_INET;
	slen = sizeof(struct sockaddr_in);
#else
	// OpenBSD requires correct family and size
	switch(family)
	{
		case AF_INET:
			slen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			slen = sizeof(struct sockaddr_in6);
			break;
		default:
			return -1;
	}
#endif
	memset(&sa,0,slen);
	sa.ss_family = family;
	return sendto(sock, buf, len, 0, (struct sockaddr*)&sa, slen);
}
#endif

static int rawsend_socket_raw(int domain, int proto)
{
	int fd = socket(domain, SOCK_RAW, proto);
	if (fd!=-1)
	{
		#ifdef __linux__
		int s=RAW_SNDBUF/2;
		int r=2048;
		#else
		int s=RAW_SNDBUF;
		int r=4096;
		#endif
		if (!set_socket_buffers(fd,r,s))
		{
			close(fd);
			return -1;
		}
	}
	return fd;
}

static bool set_socket_fwmark(int sock, uint32_t fwmark)
{
#ifdef BSD
#ifdef SO_USER_COOKIE
	if (setsockopt(sock, SOL_SOCKET, SO_USER_COOKIE, &fwmark, sizeof(fwmark)) == -1)
	{
		DLOG_PERROR("rawsend: setsockopt(SO_USER_COOKIE)");
		return false;
	}
#endif
#elif defined(__linux__)
	if (setsockopt(sock, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark)) == -1)
	{
		DLOG_PERROR("rawsend: setsockopt(SO_MARK)");
		return false;
	}

#endif
	return true;
}

static int rawsend_socket(sa_family_t family)
{
	int *sock = rawsend_family_sock(family);
	if (!sock) return -1;
	
	if (*sock==-1)
	{
		int yes=1,pri=6;
		//printf("rawsend_socket: family %d",family);

#ifdef __FreeBSD__
		// IPPROTO_RAW with ipv6 in FreeBSD always returns EACCES on sendto.
		// must use IPPROTO_TCP for ipv6. IPPROTO_RAW works for ipv4
		// divert sockets are always v4 but accept both v4 and v6
		*sock = rawsend_socket_divert(AF_INET);
#elif defined(__OpenBSD__) || defined (__APPLE__)
		// OpenBSD does not allow sending TCP frames through raw sockets
		// I dont know about macos. They have dropped ipfw in recent versions and their PF does not support divert-packet
		*sock = rawsend_socket_divert(family);
#else
		*sock = rawsend_socket_raw(family, IPPROTO_RAW);
#endif
		if (*sock==-1)
		{
			DLOG_PERROR("rawsend: socket()");
			return -1;
		}
#ifdef __linux__
		if (setsockopt(*sock, SOL_SOCKET, SO_PRIORITY, &pri, sizeof(pri)) == -1)
		{
			DLOG_PERROR("rawsend: setsockopt(SO_PRIORITY)");
			goto exiterr;
		}
		if (family==AF_INET && setsockopt(*sock, IPPROTO_IP, IP_NODEFRAG, &yes, sizeof(yes)) == -1)
		{
			DLOG_PERROR("rawsend: setsockopt(IP_NODEFRAG)");
			goto exiterr;
		}
		if (family==AF_INET && setsockopt(*sock, IPPROTO_IP, IP_FREEBIND, &yes, sizeof(yes)) == -1)
		{
			DLOG_PERROR("rawsend: setsockopt(IP_FREEBIND)");
			goto exiterr;
		}
		if (family==AF_INET6 && setsockopt(*sock, SOL_IPV6, IPV6_FREEBIND, &yes, sizeof(yes)) == -1)
		{
			//DLOG_PERROR("rawsend: setsockopt(IPV6_FREEBIND)");
			// dont error because it's supported only from kernel 4.15
		}
#endif
	}
	return *sock;
exiterr:
	rawsend_clean_sock(sock);
	return -1;
}
bool rawsend_preinit(bool bind_fix4, bool bind_fix6)
{
	b_bind_fix4 = bind_fix4;
	b_bind_fix6 = bind_fix6;
	// allow ipv6 disabled systems
	return rawsend_socket(AF_INET)!=-1 && (rawsend_socket(AF_INET6)!=-1 || errno==EAFNOSUPPORT);
}
bool rawsend(const struct sockaddr* dst,uint32_t fwmark,const char *ifout,const void *data,size_t len)
{
	ssize_t bytes;
	int sock=rawsend_socket(dst->sa_family);
	if (sock==-1) return false;
	if (!set_socket_fwmark(sock,fwmark)) return false;
	int salen = dst->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	struct sockaddr_storage dst2;
	memcpy(&dst2,dst,salen);
	if (dst->sa_family==AF_INET6)
		((struct sockaddr_in6 *)&dst2)->sin6_port = 0; // or will be EINVAL in linux

#if defined(BSD)
	bytes = rawsend_sendto_divert(dst->sa_family,sock,data,len);
	if (bytes==-1)
	{
		DLOG_PERROR("rawsend: sendto_divert");
		return false;
	}
	return true;

#else

#ifdef __linux__
	struct sockaddr_storage sa_src;
	switch(dst->sa_family)
	{
		case AF_INET:
			if (!b_bind_fix4) goto nofix;
			extract_endpoints(data,NULL,NULL,NULL, &sa_src, NULL);
			break;
		case AF_INET6:
			if (!b_bind_fix6) goto nofix;
			extract_endpoints(NULL,data,NULL,NULL, &sa_src, NULL);
			break;
		default:
			return false; // should not happen
	}
	//printf("family %u dev %s bind : ",  dst->sa_family, ifout); print_sockaddr((struct sockaddr *)&sa_src); printf("\n");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifout, ifout ? strlen(ifout)+1 : 0) == -1)
	{
		DLOG_PERROR("rawsend: setsockopt(SO_BINDTODEVICE)");
		return false;
	}
	if (bind(sock, (const struct sockaddr*)&sa_src, dst->sa_family==AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))
	{
		DLOG_PERROR("rawsend: bind (ignoring)");
		// do not fail. this can happen regardless of IP_FREEBIND
		// rebind to any address
		memset(&sa_src,0,sizeof(sa_src));
		sa_src.ss_family = dst->sa_family;
		if (bind(sock, (const struct sockaddr*)&sa_src, dst->sa_family==AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))
		{
			DLOG_PERROR("rawsend: bind to any");
			return false;
		}
	}
nofix:
#endif

	// normal raw socket sendto
	bytes = sendto(sock, data, len, 0, (struct sockaddr*)&dst2, salen);
	if (bytes==-1)
	{
		char s[40];
		snprintf(s,sizeof(s),"rawsend: sendto (%zu)",len);
		DLOG_PERROR(s);
		return false;
	}
	return true;
#endif
}

#endif // not CYGWIN


bool rawsend_rep(int repeats, const struct sockaddr* dst, uint32_t fwmark, const char *ifout, const void *data, size_t len)
{
	for (int i = 0; i < repeats; i++)
		if (!rawsend(dst, fwmark, ifout, data, len))
			return false;
	return true;
}

bool rawsend_rp(const struct rawpacket *rp)
{
	return rawsend((struct sockaddr*)&rp->dst,rp->fwmark,rp->ifout,rp->packet,rp->len);
}
bool rawsend_queue(struct rawpacket_tailhead *q)
{
	struct rawpacket *rp;
	bool b;
	for (b=true; (rp=rawpacket_dequeue(q)) ; rawpacket_free(rp))
		b &= rawsend_rp(rp);
	return b;
}



#if defined(HAS_FILTER_SSID) && defined(__linux__)

// linux-specific wlan retrieval implementation

typedef void netlink_prepare_nlh_cb_t(struct nlmsghdr *nlh, void *param);

static bool netlink_genl_simple_transact(struct mnl_socket* nl, uint16_t type, uint16_t flags, uint8_t cmd, uint8_t version, netlink_prepare_nlh_cb_t cb_prepare_nlh, void *prepare_data, mnl_cb_t cb_data, void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	ssize_t rd;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= type;
	nlh->nlmsg_flags = flags;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = cmd;
	genl->version = version;

	if (cb_prepare_nlh) cb_prepare_nlh(nlh, prepare_data);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
	{
		DLOG_PERROR("mnl_socket_sendto");
		return false;
	}

	while ((rd=mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0)
	{
		switch(mnl_cb_run(buf, rd, 0, 0, cb_data, data))
		{
			case MNL_CB_STOP:
				return true;
			case MNL_CB_OK:
				break;
			default:
				return false;
		}
	}

	return false;
}

static void wlan_id_prepare(struct nlmsghdr *nlh, void *param)
{
	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, "nl80211");
}
static int wlan_id_attr_cb(const struct nlattr *attr, void *data)
{
	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
	{
		DLOG_PERROR("mnl_attr_type_valid");
		return MNL_CB_ERROR;
	}

	switch(mnl_attr_get_type(attr))
	{
		case CTRL_ATTR_FAMILY_ID:
			if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
			{
				DLOG_PERROR("mnl_attr_validate(family_id)");
				return MNL_CB_ERROR;
			}
			*((uint16_t*)data) = mnl_attr_get_u16(attr);
		break;
	}
	return MNL_CB_OK;
}
static int wlan_id_cb(const struct nlmsghdr *nlh, void *data)
{
	return mnl_attr_parse(nlh, sizeof(struct genlmsghdr), wlan_id_attr_cb, data);
}
static uint16_t wlan_get_family_id(struct mnl_socket* nl)
{
	uint16_t id;
	return netlink_genl_simple_transact(nl, GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, CTRL_CMD_GETFAMILY, 1, wlan_id_prepare, NULL, wlan_id_cb, &id) ? id : 0;
}

static int wlan_info_attr_cb(const struct nlattr *attr, void *data)
{
	struct wlan_interface *wlan = (struct wlan_interface *)data;
	switch(mnl_attr_get_type(attr))
	{
		case NL80211_ATTR_IFINDEX:
			if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			{
				DLOG_PERROR("mnl_attr_validate(ifindex)");
				return MNL_CB_ERROR;
			}
			wlan->ifindex = mnl_attr_get_u32(attr);
			break;
		case NL80211_ATTR_SSID:
			if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			{
				DLOG_PERROR("mnl_attr_validate(ssid)");
				return MNL_CB_ERROR;
			}
			snprintf(wlan->ssid,sizeof(wlan->ssid),"%s",mnl_attr_get_str(attr));
			break;
		case NL80211_ATTR_IFNAME:
			if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			{
				DLOG_PERROR("mnl_attr_validate(ifname)");
				return MNL_CB_ERROR;
			}
			snprintf(wlan->ifname,sizeof(wlan->ifname),"%s",mnl_attr_get_str(attr));
			break;
	}
	return MNL_CB_OK;
}
struct wlan_info_req
{
	struct wlan_interface_collection *wc;
	bool bReqSSID;
};
static int wlan_info_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	struct wlan_info_req *wr = (struct wlan_info_req*)data;
	if (wr->wc->count>=WLAN_INTERFACE_MAX) return MNL_CB_OK;
	memset(wr->wc->wlan + wr->wc->count,0,sizeof(struct wlan_interface));
	ret = mnl_attr_parse(nlh, sizeof(struct genlmsghdr), wlan_info_attr_cb, wr->wc->wlan + wr->wc->count);
	if (ret>=0 && (!wr->bReqSSID || *wr->wc->wlan[wr->wc->count].ssid) && *wr->wc->wlan[wr->wc->count].ifname && wr->wc->wlan[wr->wc->count].ifindex)
		wr->wc->count++;
	return ret;
}
static bool wlan_info(struct mnl_socket* nl, uint16_t wlan_family_id, struct wlan_interface_collection* w, bool bReqSSID)
{
	struct wlan_info_req req = { .bReqSSID = bReqSSID, .wc = w };
	return netlink_genl_simple_transact(nl, wlan_family_id, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0, NULL, NULL, wlan_info_cb, &req);
}


static void scan_prepare(struct nlmsghdr *nlh, void *param)
{
	mnl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, *(int*)param);
}
static uint8_t *find_ie(uint8_t *buf, size_t len, uint8_t ie)
{
	while (len>=2)
	{
		if (len<(2+buf[1])) break;
		if (buf[0]==ie) return buf;
		buf+=buf[1]+2;
		len-=buf[1]+2;
	}
	return NULL;
}
static int scan_info_attr_cb(const struct nlattr *attr, void *data)
{
	struct wlan_interface *wlan = (struct wlan_interface *)data;
	const struct nlattr *nested;
	uint8_t *payload, *ie;
	uint16_t payload_len;
	bool ok;

	switch(mnl_attr_get_type(attr))
	{
		case NL80211_ATTR_IFINDEX:
			if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			{
				DLOG_PERROR("mnl_attr_validate");
				return MNL_CB_ERROR;
			}
			wlan->ifindex = mnl_attr_get_u32(attr);
			if (!if_indextoname(wlan->ifindex, wlan->ifname))
				DLOG_PERROR("if_indextoname");
			break;
		case NL80211_ATTR_BSS:
			if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			{
				DLOG_PERROR("mnl_attr_validate");
				return MNL_CB_ERROR;
			}
			ok = false;
			mnl_attr_for_each_nested(nested, attr)
			{
				if (mnl_attr_get_type(nested)==NL80211_BSS_STATUS)
				{
					uint32_t status = mnl_attr_get_u32(nested);
					if (status==NL80211_BSS_STATUS_ASSOCIATED || status==NL80211_BSS_STATUS_AUTHENTICATED || status==NL80211_BSS_STATUS_IBSS_JOINED)
					{
						ok=1;
						break;
					}
				}
			}
			if (!ok) break;
			mnl_attr_for_each_nested(nested, attr)
			{
				switch(mnl_attr_get_type(nested))
				{
					case NL80211_BSS_INFORMATION_ELEMENTS:
						payload_len = mnl_attr_get_payload_len(nested);
						payload = mnl_attr_get_payload(nested);
						ie = find_ie(payload,payload_len,0);
						if (ie)
						{
							uint8_t l = ie[1];
							if (l>=(sizeof(wlan->ssid))) l=sizeof(wlan->ssid)-1;
							memcpy(wlan->ssid,ie+2,l);
							wlan->ssid[l]=0;
						}
						break;
				}
			}
			break;
	}
	return MNL_CB_OK;
}
static int scan_info_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	struct wlan_interface_collection *wc = (struct wlan_interface_collection*)data;
	if (wc->count>=WLAN_INTERFACE_MAX) return MNL_CB_OK;
	memset(wc->wlan+wc->count,0,sizeof(wc->wlan[0]));
	ret = mnl_attr_parse(nlh, sizeof(struct genlmsghdr), scan_info_attr_cb, wc->wlan+wc->count);
	if (ret>=0 && *wc->wlan[wc->count].ssid && *wc->wlan[wc->count].ifname && wc->wlan[wc->count].ifindex)
		wc->count++;
	return ret;
}
static bool scan_info(struct mnl_socket* nl, uint16_t wlan_family_id, struct wlan_interface_collection* w)
{
	struct wlan_interface_collection wc_all = { .count = 0 };
	// wlan_info does not return ssid since kernel 5.19
	// it's used to enumerate all wifi interfaces then call scan_info on each
	if (!wlan_info(nl, wlan_family_id, &wc_all, false)) return false;
	for(int i=0;i<wc_all.count;i++)
		if (!netlink_genl_simple_transact(nl, wlan_family_id, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0, scan_prepare, (void*)&wc_all.wlan[i].ifindex, scan_info_cb, w))
			return false;
	return true;
}


static bool wlan_init80211(struct mnl_socket** nl)
{
	if (!(*nl = mnl_socket_open(NETLINK_GENERIC)))
	{
		DLOG_PERROR("mnl_socket_open");
		return false;
	}
	if (mnl_socket_bind(*nl, 0, MNL_SOCKET_AUTOPID))
	{
		DLOG_PERROR("mnl_socket_bind");
		return false;
	}
	return true;
}

static void wlan_deinit80211(struct mnl_socket** nl)
{
	if (*nl)
	{
		mnl_socket_close(*nl);
		*nl = NULL;
	}
}

static time_t wlan_info_last = 0;
static bool wlan_info_rate_limited(struct mnl_socket* nl, uint16_t wlan_family_id, struct wlan_interface_collection* w)
{
	bool bres = true;
	time_t now = time(NULL);

	// do not purge too often to save resources
	if (wlan_info_last != now)
	{
		bres = scan_info(nl,wlan_family_id,w);
		wlan_info_last = now;
	}
	return bres;
}

static struct mnl_socket* nl_wifi = NULL;
static uint16_t id_nl80211;
struct wlan_interface_collection wlans = { .count = 0 };

void wlan_info_deinit(void)
{
	wlan_deinit80211(&nl_wifi);
}
bool wlan_info_init(void)
{
	wlan_info_deinit();

	if (!wlan_init80211(&nl_wifi)) return false;
	if (!(id_nl80211 = wlan_get_family_id(nl_wifi)))
	{
		wlan_info_deinit();
		return false;
	}
	return true;
}
bool wlan_info_get_rate_limited(void)
{
	return wlan_info_rate_limited(nl_wifi, id_nl80211, &wlans);
}

#endif


#ifdef HAS_FILTER_SSID
const char *wlan_ifname2ssid(const struct wlan_interface_collection *w, const char *ifname)
{
	int i;
	if (ifname)
	{
		for (i=0;i<w->count;i++)
			if (!strcmp(w->wlan[i].ifname,ifname))
				return w->wlan[i].ssid;
	}
	return NULL;
}
const char *wlan_ifidx2ssid(const struct wlan_interface_collection *w,int ifidx)
{
	int i;
	for (i=0;i<w->count;i++)
		if (w->wlan[i].ifindex == ifidx)
			return w->wlan[i].ssid;
	return NULL;
}
const char *wlan_ssid_search_ifname(const char *ifname)
{
	return wlan_ifname2ssid(&wlans,ifname);
}
const char *wlan_ssid_search_ifidx(int ifidx)
{
	return wlan_ifidx2ssid(&wlans,ifidx);
}

#endif


void verdict_tcp_csum_fix(uint8_t verdict, struct tcphdr *tcphdr, size_t transport_len, const struct ip *ip, const struct ip6_hdr *ip6hdr)
{
	// always fix csum for windivert. original can be partial or bad
	// FreeBSD tend to pass ipv6 frames with wrong checksum (OBSERVED EARLIER, MAY BE FIXED NOW)
	// Linux passes correct checksums
#ifndef __linux__
	if (!(verdict & VERDICT_NOCSUM) && (verdict & VERDICT_MASK)==VERDICT_PASS)
	{
		#ifdef __FreeBSD__
		if (ip6hdr)
		#endif
		{
			DLOG("fixing tcp checksum\n");
			tcp_fix_checksum(tcphdr,transport_len,ip,ip6hdr);
		}
	}
#endif
}
void verdict_udp_csum_fix(uint8_t verdict, struct udphdr *udphdr, size_t transport_len, const struct ip *ip, const struct ip6_hdr *ip6hdr)
{
	// always fix csum for windivert. original can be partial or bad
	// FreeBSD tend to pass ipv6 frames with wrong checksum (OBSERVED EARLIER, MAY BE FIXED NOW)
	// Linux passes correct checksums
#ifndef __linux__
	if (!(verdict & VERDICT_NOCSUM) && (verdict & VERDICT_MASK)==VERDICT_PASS)
	{
		#ifdef __FreeBSD__
		if (ip6hdr)
		#endif
			DLOG("fixing udp checksum\n");
			udp_fix_checksum(udphdr,transport_len,ip,ip6hdr);
	}
#endif
}

void dbgprint_socket_buffers(int fd)
{
	if (params.debug)
	{
		int v;
		socklen_t sz;
		sz = sizeof(int);
		if (!getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, &sz))
			DLOG("fd=%d SO_RCVBUF=%d\n", fd, v);
			sz = sizeof(int);
		if (!getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, &sz))
			DLOG("fd=%d SO_SNDBUF=%d\n", fd, v);
	}
}
bool set_socket_buffers(int fd, int rcvbuf, int sndbuf)
{
	DLOG("set_socket_buffers fd=%d rcvbuf=%d sndbuf=%d\n", fd, rcvbuf, sndbuf);
	if (rcvbuf && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int)) < 0)
	{
		DLOG_PERROR("setsockopt (SO_RCVBUF)");
		return false;
	}
	if (sndbuf && setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int)) < 0)
	{
		DLOG_PERROR("setsockopt (SO_SNDBUF)");
		return false;
	}
	dbgprint_socket_buffers(fd);
	return true;
}

bool make_writeable_dir()
{
	char wdir[PATH_MAX], *wrdir;
	if (*params.writeable_dir)
		wrdir = params.writeable_dir;
	else
	{
#ifdef __CYGWIN__
		char *env = getenv("APPDATALOW");
		if (!env) return false;
#else
		char *env = getenv("TMPDIR");
		if (!env) env = "/tmp";
#endif
		snprintf(wdir,sizeof(wdir),"%s/zapret2",env);
		wrdir = wdir;
	}
	if (mkdir(wrdir,0755) && errno!=EEXIST)
		return false;

	bool b = false;
#ifdef __CYGWIN__
	size_t l = cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, wrdir, NULL, 0);
	WCHAR *wwrdir = (WCHAR*)malloc(l);
	if (wwrdir)
	{
		if (!cygwin_conv_path(CCP_POSIX_TO_WIN_W | CCP_ABSOLUTE, wrdir, wwrdir, l))
			b = SetMandatoryLabelFileW(wwrdir, SECURITY_MANDATORY_LOW_RID, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
		free(wwrdir);
	}
#else
	if (ensure_dir_access(wrdir))
		b = true;
	else
	{
		// could not chown. may be still accessible ?
		char testfile[PATH_MAX];
		snprintf(testfile,sizeof(testfile),"%s/test_XXXXXX",wrdir);
		int fd = mkstemp(testfile);
		if (fd>0)
		{
			close(fd);
			unlink(testfile);
			b = true;
		}
	}
#endif
	if (b) setenv("WRITEABLE",wrdir,1);
	return b;
}
