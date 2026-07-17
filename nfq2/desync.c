#define _GNU_SOURCE

#include <string.h>
#include <errno.h>

#include "desync.h"
#include "protocol.h"
#include "params.h"
#include "helpers.h"
#include "hostlist.h"
#include "ipset.h"
#include "conntrack.h"
#include "lua.h"

#define PKTDATA_MAXDUMP 32
#define IP_MAXDUMP 80

#define TCP_MAX_REASM 16384
#define UDP_MAX_REASM 16384

typedef	struct
{
	t_l7payload l7p;
	t_l7proto l7;
	bool(*check)(const uint8_t*, size_t);
	bool l7match;
} t_protocol_probe;

static void protocol_probe(t_protocol_probe *probe, int probe_count, const uint8_t *data_payload, size_t len_payload, t_ctrack *ctrack, t_l7proto *l7proto, t_l7payload *l7payload)
{
	for (int i = 0; i < probe_count; i++)
	{
		if (!l7_payload_match(probe[i].l7p, params.payload_disable) && (!probe[i].l7match || *l7proto==probe[i].l7) && probe[i].check(data_payload, len_payload))
		{
			*l7payload = probe[i].l7p;
			if (*l7proto == L7_UNKNOWN)
			{
				*l7proto = probe[i].l7;
				if (ctrack && ctrack->l7proto == L7_UNKNOWN) ctrack->l7proto = *l7proto;
			}
			DLOG("packet contains %s payload\n", l7payload_str(*l7payload));
			break;
		}
	}
}


static void TLSDebugHandshake(const uint8_t *tls, size_t sz)
{
	if (!params.debug) return;

	if (sz < 6) return;

	const uint8_t *ext;
	size_t len, len2;
	bool bServerHello = IsTLSHandshakeServerHello(tls, sz, true);

	uint16_t v_handshake = pntoh16(tls + 4), v, v2;
	DLOG("TLS handshake version : %s\n", TLSVersionStr(v_handshake));

	if (TLSFindExtInHandshake(tls, sz, 43, &ext, &len, false))
	{
		if (len)
		{
			if (bServerHello)
			{
				v = pntoh16(ext);
				DLOG("TLS supported versions ext : %s\n", TLSVersionStr(v));
			}
			else
			{
				len2 = ext[0];
				if (len2 < len)
				{
					for (ext++, len2 &= ~1; len2; len2 -= 2, ext += 2)
					{
						v = pntoh16(ext);
						DLOG("TLS supported versions ext : %s\n", TLSVersionStr(v));
					}
				}
			}
		}
	}
	else
		DLOG("TLS supported versions ext : not present\n");

	if (!bServerHello)
	{
		if (TLSFindExtInHandshake(tls, sz, 16, &ext, &len, false))
		{
			if (len >= 2)
			{
				len2 = pntoh16(ext);
				if (len2 <= (len - 2))
				{
					char s[32];
					for (ext += 2; len2;)
					{
						v = *ext; ext++; len2--;
						if (v <= len2)
						{
							v2 = v < sizeof(s) ? v : sizeof(s) - 1;
							memcpy(s, ext, v2);
							s[v2] = 0;
							DLOG("TLS ALPN ext : %s\n", s);
							len2 -= v;
							ext += v;
						}
						else
							break;
					}
				}
			}
		}
		else
			DLOG("TLS ALPN ext : not present\n");

		DLOG("TLS ECH ext : %s\n", TLSFindExtInHandshake(tls, sz, 65037, NULL, NULL, false) ? "present" : "not present");
	}
}
static void TLSDebug(const uint8_t *tls, size_t sz)
{
	if (!params.debug) return;

	if (sz < 11) return;

	DLOG("TLS record layer version : %s\n", TLSVersionStr(pntoh16(tls + 1)));

	size_t reclen = TLSRecordLen(tls);
	if (reclen < sz) sz = reclen; // correct len if it has more data than the first tls record has

	TLSDebugHandshake(tls + 5, sz - 5);
}

static void packet_debug(bool replay, const struct dissect *dis)
{
	if (params.debug)
	{
		if (replay) DLOG("REPLAY ");
		if (dis->ip)
		{
			char s[66];
			str_ip(s, sizeof(s), dis->ip);
			DLOG("IP4: %s", s);
		}
		else if (dis->ip6)
		{
			char s[128];
			str_ip6hdr(s, sizeof(s), dis->ip6, dis->proto);
			DLOG("IP6: %s", s);
		}

		if (dis->tcp)
		{
			char s[80];
			str_tcphdr(s, sizeof(s), dis->tcp);
			DLOG(" %s\n", s);
			if (dis->len_payload)
			{
				DLOG("TCP: len=%zu : ", dis->len_payload);
				hexdump_limited_dlog(dis->data_payload, dis->len_payload, PKTDATA_MAXDUMP);
				DLOG("\n");
			}
		}
		else if (dis->udp)
		{
			char s[30];
			str_udphdr(s, sizeof(s), dis->udp);
			DLOG(" %s\n", s);
			if (dis->len_payload)
			{
				DLOG("UDP: len=%zu : ", dis->len_payload);
				hexdump_limited_dlog(dis->data_payload, dis->len_payload, PKTDATA_MAXDUMP);
				DLOG("\n");
			}
		}
		else if (dis->icmp)
		{
			char s[72];
			str_icmphdr(s, sizeof(s), !!dis->ip6, dis->icmp);
			DLOG(" %s\nICMP: len=%zu : ", s, dis->len_payload);
			hexdump_limited_dlog(dis->data_payload, dis->len_payload, PKTDATA_MAXDUMP);
			DLOG("\n");
		}
		else
		{
			if (dis->len_payload)
			{
				char s_proto[16];
				str_proto_name(s_proto,sizeof(s_proto),dis->proto);
				if (dis->frag)
					DLOG("\nIP FRAG off=%u PROTO %s: len=%zu : ", dis->frag_off, s_proto, dis->len_payload);
				else
					DLOG("\nIP PROTO %s: len=%zu : ", s_proto, dis->len_payload);
				hexdump_limited_dlog(dis->data_payload, dis->len_payload, PKTDATA_MAXDUMP);
				DLOG("\n");
			}
			else
				DLOG("\n");
		}
	}
}

// ipr,ipr6 - reverse ip - ip of the other side of communication
static bool dp_match(
	struct desync_profile *dp,
	uint8_t l3proto,
	const struct in_addr *ip, const struct in6_addr *ip6,
	const struct in_addr *ipr, const struct in6_addr *ipr6,
	uint16_t port, uint8_t icmp_type, uint8_t icmp_code,
	const char *hostname, bool bNoSubdom, t_l7proto l7proto, const char *ssid,
	bool *bCheckDone, bool *bCheckResult, bool *bExcluded)
{
	bool bHostlistsEmpty;

	if (bCheckDone) *bCheckDone = false;

	if (!HostlistsReloadCheckForProfile(dp)) return false;

	if ((ip && !dp->filter_ipv4) || (ip6 && !dp->filter_ipv6))
		// L3 filter does not match
		return false;

	switch(l3proto)
	{
		case IPPROTO_TCP:
			if (!port_filters_match(&dp->pf_tcp, port)) return false;
			break;
		case IPPROTO_UDP:
			if (!port_filters_match(&dp->pf_udp, port)) return false;
			break;
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			if (!icmp_filters_match(&dp->icf, icmp_type, icmp_code)) return false;
			break;
		default:
			if (!ipp_filters_match(&dp->ipf, l3proto)) return false;
	}

	if (!l7_proto_match(l7proto, dp->filter_l7))
		// L7 filter does not match
		return false;
#ifdef HAS_FILTER_SSID
	if (!LIST_EMPTY(&dp->filter_ssid) && !strlist_search(&dp->filter_ssid, ssid))
		return false;
#endif

	bHostlistsEmpty = PROFILE_HOSTLISTS_EMPTY(dp);
	if (!dp->hostlist_auto && !hostname && !bHostlistsEmpty)
		// avoid cpu consuming ipset check. profile cannot win if regular hostlists are present without auto hostlist and hostname is unknown.
		return false;
	if (!IpsetCheck(dp, ip, ip6, ipr, ipr6))
		// target ip does not match
		return false;

	// autohostlist profile matching l3/l4/l7 filter always win if we have a hostname. no matter it matches or not.
	if (dp->hostlist_auto && hostname)
	{
		DLOG("autohostlist profile %u (%s) wins because hostname is known\n",dp->n,dp->name);
		return true;
	}

	if (bHostlistsEmpty)
		// profile without hostlist filter wins
		return true;
	else
	{
		// if hostlists are present profile matches only if hostname is known and satisfy profile hostlists
		if (hostname)
		{
			if (bCheckDone) *bCheckDone = true;
			bool b;
			b = HostlistCheck(dp, hostname, bNoSubdom, bExcluded, true);
			if (bCheckResult) *bCheckResult = b;
			return b;
		}
	}
	return false;
}
static struct desync_profile *dp_find(
	struct desync_profile_list_head *head,
	uint8_t l3proto,
	const struct in_addr *ip, const struct in6_addr *ip6,
	const struct in_addr *ipr, const struct in6_addr *ipr6,
	uint16_t port, uint8_t icmp_type, uint8_t icmp_code,
	const char *hostname, bool bNoSubdom, t_l7proto l7proto, const char *ssid,
	bool *bCheckDone, bool *bCheckResult, bool *bExcluded)
{
	struct desync_profile_list *dpl;
	if (params.debug)
	{
		char s[INET6_ADDRSTRLEN];
		ntopa46(ip, ip6, s, sizeof(s));
		if (ipr || ipr6)
		{
			char sr[INET6_ADDRSTRLEN];
			ntopa46(ipr, ipr6, sr, sizeof(sr));
			DLOG("desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' hostname='%s'\n",
				proto_name(l3proto), s, sr, port, icmp_type, icmp_code, l7proto_str(l7proto), ssid ? ssid : "", hostname ? hostname : "");
		}
		else
			DLOG("desync profile search for %s ip=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' hostname='%s'\n",
				proto_name(l3proto), s, port, icmp_type, icmp_code, l7proto_str(l7proto), ssid ? ssid : "", hostname ? hostname : "");
	}
	if (bCheckDone) *bCheckDone = false;
	LIST_FOREACH(dpl, head, next)
	{
		if (dp_match(&dpl->dp, l3proto, ip, ip6, ipr, ipr6, port, icmp_type, icmp_code, hostname, bNoSubdom, l7proto, ssid, bCheckDone, bCheckResult, bExcluded))
		{
			DLOG("desync profile %u (%s) matches\n", dpl->dp.n, PROFILE_NAME(&dpl->dp));
			return &dpl->dp;
		}
	}
	DLOG("desync profile not found\n");
	return NULL;
}


static void ctrack_stop_retrans_counter(t_ctrack *ctrack)
{
	if (ctrack && ctrack->hostname_ah_check)
		ctrack->req_retrans_counter = RETRANS_COUNTER_STOP;
}

static void auto_hostlist_reset_fail_counter(struct desync_profile *dp, const char *hostname, const char *client_ip_port, t_l7proto l7proto)
{
	if (hostname)
	{
		hostfail_pool *fail_counter;

		fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
		if (fail_counter)
		{
			HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);
			DLOG("auto hostlist (profile %u (%s)) : %s : fail counter reset. website is working.\n", dp->n, PROFILE_NAME(dp), hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : fail counter reset. website is working.", hostname, dp->n, PROFILE_NAME(dp), client_ip_port, l7proto_str(l7proto));
		}
	}
}

static bool is_retransmission(const t_ctrack_position *pos)
{
	return !((pos->uppos_prev - pos->pos) & 0x80000000);
}

// return true if retrans trigger fires
static bool auto_hostlist_retrans
 (t_ctrack *ctrack, const struct dissect *dis, int threshold, const char *client_ip_port, t_l7proto l7proto,
	const struct sockaddr *client, const char *ifclient)
{
	if (ctrack && ctrack->dp && ctrack->hostname_ah_check && !ctrack->failure_detect_finalized && ctrack->req_retrans_counter != RETRANS_COUNTER_STOP)
	{
		if (dis->proto == IPPROTO_TCP && ctrack->pos.state!=SYN)
		{
			if (!seq_within(ctrack->pos.client.seq_last, ctrack->pos.client.seq0, ctrack->pos.client.seq0 + ctrack->dp->hostlist_auto_retrans_maxseq))
			{
				ctrack->failure_detect_finalized = true;
				DLOG("retrans : tcp seq %u not within range %u-%u. stop tracking.\n", ctrack->pos.client.seq_last, ctrack->pos.client.seq0, ctrack->pos.client.seq0 + ctrack->dp->hostlist_auto_retrans_maxseq);
				ctrack_stop_retrans_counter(ctrack);
				auto_hostlist_reset_fail_counter(ctrack->dp, ctrack->hostname, client_ip_port, l7proto);
				return false;
			}
			if (!is_retransmission(&ctrack->pos.client))
				return false;
		}
		ctrack->req_retrans_counter++;
		if (ctrack->req_retrans_counter >= threshold)
		{
			DLOG("retrans threshold reached : %u/%u\n", ctrack->req_retrans_counter, threshold);
			ctrack_stop_retrans_counter(ctrack);
			ctrack->failure_detect_finalized = true;
			if (dis->tcp && ctrack->dp->hostlist_auto_retrans_reset && (dis->ip || dis->ip6))
			{
				uint8_t pkt[sizeof(struct ip6_hdr)+sizeof(struct tcphdr)];
				struct ip *ip=NULL;
				struct ip6_hdr *ip6=NULL;
				struct tcphdr *tcp;
				uint16_t pktlen;

				if (dis->ip)
				{
					ip = (struct ip*)pkt;
					pktlen = sizeof(struct ip) + sizeof(struct tcphdr);
					*ip = *dis->ip;
					ip->ip_hl = sizeof(struct ip)/4; // remove ip options
					ip->ip_len = htons(pktlen);
					ip->ip_id=0;
					tcp = (struct tcphdr*)(ip+1);
					*tcp = *dis->tcp;
				}
				else if (dis->ip6)
				{
					ip6 = (struct ip6_hdr*)pkt;
					pktlen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
					*ip6 = *dis->ip6;
					ip6->ip6_plen = htons(sizeof(struct tcphdr));
					ip6->ip6_nxt = IPPROTO_TCP;
					ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(ctrack->pos.server.ip6flow ? ctrack->pos.server.ip6flow : 0x60000000);
					tcp = (struct tcphdr*)(ip6+1);
					*tcp = *dis->tcp;
				}
				else
					return true; // should never happen

				reverse_ip(ip,ip6); // also fixes ip4 checksum
				reverse_tcp(tcp);
				tcp->th_off = sizeof(struct tcphdr)/4; // remove tcp options
				tcp->th_flags = TH_RST;
				tcp->th_win = ctrack->pos.server.winsize;
				tcp_fix_checksum(tcp, sizeof(struct tcphdr), ip, ip6);

				DLOG("sending RST to retransmitter. ifname=%s\n", ifclient ? ifclient : "");
				rawsend(client,0,ifclient,pkt,pktlen);
			}
			return true;
		}
		DLOG("retrans counter : %u/%u\n", ctrack->req_retrans_counter, threshold);
	}
	return false;
}
static void auto_hostlist_failed(struct desync_profile *dp, const char *hostname, bool bNoSubdom, const char *client_ip_port, t_l7proto l7proto)
{
	hostfail_pool *fail_counter;

	fail_counter = HostFailPoolFind(dp->hostlist_auto_fail_counters, hostname);
	if (!fail_counter)
	{
		fail_counter = HostFailPoolAdd(&dp->hostlist_auto_fail_counters, hostname, dp->hostlist_auto_fail_time);
		if (!fail_counter)
		{
			DLOG_ERR("HostFailPoolAdd: out of memory\n");
			return;
		}
	}
	fail_counter->counter++;
	DLOG("auto hostlist (profile %u (%s)) : %s : fail counter %d/%d\n", dp->n, PROFILE_NAME(dp), hostname, fail_counter->counter, dp->hostlist_auto_fail_threshold);
	HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : fail counter %d/%d", hostname, dp->n, PROFILE_NAME(dp), client_ip_port, l7proto_str(l7proto), fail_counter->counter, dp->hostlist_auto_fail_threshold);
	if (fail_counter->counter >= dp->hostlist_auto_fail_threshold)
	{
		DLOG("auto hostlist (profile %u (%s)) : fail threshold reached. about to add %s to auto hostlist\n", dp->n, PROFILE_NAME(dp), hostname);
		HostFailPoolDel(&dp->hostlist_auto_fail_counters, fail_counter);

		DLOG("auto hostlist (profile %u (%s)) : rechecking %s to avoid duplicates\n", dp->n, PROFILE_NAME(dp), hostname);
		bool bExcluded = false;
		if (!HostlistCheck(dp, hostname, bNoSubdom, &bExcluded, false) && !bExcluded)
		{
			DLOG("auto hostlist (profile %u) : adding %s to %s\n", dp->n, hostname, dp->hostlist_auto->filename);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : adding to %s", hostname, dp->n, PROFILE_NAME(dp), client_ip_port, l7proto_str(l7proto), dp->hostlist_auto->filename);
			if (!HostlistPoolAddStr(&dp->hostlist_auto->hostlist, hostname, 0))
			{
				DLOG_ERR("StrPoolAddStr out of memory\n");
				return;
			}
			if (!append_to_list_file(dp->hostlist_auto->filename, hostname))
			{
				DLOG_PERROR("write to auto hostlist");
				return;
			}
			if (!file_mod_signature(dp->hostlist_auto->filename, &dp->hostlist_auto->mod_sig))
				DLOG_PERROR("file_mod_signature");
		}
		else
		{
			DLOG("auto hostlist (profile %u) : NOT adding %s\n", dp->n, hostname);
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : NOT adding, duplicate detected", hostname, dp->n, PROFILE_NAME(dp), client_ip_port, l7proto_str(l7proto));
		}
	}
}
static void fill_client_ip_port(const struct sockaddr *client, char *client_ip_port, size_t client_ip_port_size)
{
	if (*params.hostlist_auto_debuglog)
		ntop46_port((struct sockaddr*)client, client_ip_port, client_ip_port_size);
	else
		*client_ip_port = 0;
}
static void process_retrans_fail(t_ctrack *ctrack, const struct dissect *dis, struct sockaddr *client, const char *ifclient)
{
	if (params.server) return; // no autohostlists in server mode

	char client_ip_port[48];
	fill_client_ip_port(client, client_ip_port, sizeof(client_ip_port));
	if (ctrack && ctrack->dp && ctrack->hostname && auto_hostlist_retrans(ctrack, dis, ctrack->dp->hostlist_auto_retrans_threshold, client_ip_port, ctrack->l7proto, client, ifclient))
	{
		HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : retrans threshold reached", ctrack->hostname, ctrack->dp->n, PROFILE_NAME(ctrack->dp), client_ip_port, l7proto_str(ctrack->l7proto));
		auto_hostlist_failed(ctrack->dp, ctrack->hostname, ctrack->hostname_is_ip, client_ip_port, ctrack->l7proto);
	}
}
static void process_udp_fail(t_ctrack *ctrack, const t_ctrack_positions *tpos, const struct sockaddr *client)
{
	// no autohostlists in server mode
	if (!params.server && ctrack && ctrack->dp && ctrack->hostname && ctrack->hostname_ah_check &&
		!ctrack->failure_detect_finalized && ctrack->dp->hostlist_auto_udp_out)
	{
		char client_ip_port[48];

		if (!tpos) tpos = &ctrack->pos;
		//printf("UDP_POS %u %u\n",tpos->client.pcounter, tpos->server.pcounter);
		if (tpos->server.pcounter > ctrack->dp->hostlist_auto_udp_in)
		{
			// success
			ctrack->failure_detect_finalized = true;
			DLOG("udp_in %u > %u\n",tpos->server.pcounter,ctrack->dp->hostlist_auto_udp_in);
			fill_client_ip_port(client, client_ip_port, sizeof(client_ip_port));
			auto_hostlist_reset_fail_counter(ctrack->dp, ctrack->hostname, client_ip_port, ctrack->l7proto);
		}
		else if (tpos->client.pcounter >= ctrack->dp->hostlist_auto_udp_out)
		{
			// failure
			ctrack->failure_detect_finalized = true;
			DLOG("udp_in %u <= %u, udp_out %u >= %u\n",tpos->server.pcounter,ctrack->dp->hostlist_auto_udp_in,tpos->client.pcounter,ctrack->dp->hostlist_auto_udp_out);
			fill_client_ip_port(client, client_ip_port, sizeof(client_ip_port));
			HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : udp_in %u<=%u udp_out %u>=%u",
				ctrack->hostname, ctrack->dp->n, PROFILE_NAME(ctrack->dp), client_ip_port, l7proto_str(ctrack->l7proto),
				tpos->server.pcounter, ctrack->dp->hostlist_auto_udp_in,
				tpos->client.pcounter, ctrack->dp->hostlist_auto_udp_out);
			auto_hostlist_failed(ctrack->dp, ctrack->hostname, ctrack->hostname_is_ip, client_ip_port, ctrack->l7proto);
		}
	}
}

static bool send_delayed(t_ctrack *ctrack)
{
	if (!rawpacket_queue_empty(&ctrack->delayed))
	{
		DLOG("SENDING %u delayed packets\n", rawpacket_queue_count(&ctrack->delayed));
		return rawsend_queue(&ctrack->delayed);
	}
	return true;
}

static bool reasm_start(t_reassemble *reasm, uint8_t proto, uint32_t seq, size_t sz, size_t szMax, const uint8_t *data_payload, size_t len_payload)
{
	ReasmClear(reasm);
	if (sz <= szMax)
	{
		if (ReasmInit(reasm, sz, seq))
		{
			ReasmFeed(reasm, seq, data_payload, len_payload);
			DLOG("starting reassemble. now we have %zu/%zu\n", reasm->size_present, reasm->size);
			return true;
		}
		else
			DLOG("reassemble init failed. out of memory\n");
	}
	else
		DLOG("unexpected large payload for reassemble: size=%zu\n", sz);
	return false;
}
static bool reasm_client_start(t_ctrack *ctrack, uint8_t proto, t_l7payload pl, size_t sz, size_t szMax, const uint8_t *data_payload, size_t len_payload)
{
	if (!ctrack) return false;
	// if pcounter==0 it means we dont know server window size - no incoming packets redirected ?
	if (proto==IPPROTO_TCP && ctrack->pos.server.pcounter && (ctrack->pos.server.winsize_calc < sz))
	{
		// this is rare but possible situation
		// server gave us too small tcp window
		// client will not send all pieces of reasm
		// if we drop packets and wait for next pieces we will see nothing but retransmissions
		DLOG("reasm cancelled because server window size %u is smaller than expected reasm size %zu\n", ctrack->pos.server.winsize_calc, sz);
		return false;
	}
	ctrack->reasm_client_payload = pl;
	return reasm_start(&ctrack->reasm_client, proto, (proto == IPPROTO_TCP) ? ctrack->pos.client.seq_last : 0, sz, szMax, data_payload, len_payload);
}
static bool reasm_feed(t_ctrack *ctrack, t_reassemble *reasm, uint8_t proto, uint32_t seq, const uint8_t *data_payload, size_t len_payload)
{
	if (ctrack && !ReasmIsEmpty(reasm))
	{
		if (ReasmFeed(reasm, seq, data_payload, len_payload))
		{
			DLOG("reassemble : feeding data payload size=%zu. now we have %zu/%zu\n", len_payload, reasm->size_present, reasm->size);
			return true;
		}
		else
		{
			ReasmClear(reasm);
			DLOG("reassemble session failed\n");
			send_delayed(ctrack);
		}
	}
	return false;
}
static bool reasm_client_feed(t_ctrack *ctrack, uint8_t proto, const uint8_t *data_payload, size_t len_payload)
{
	if (!ctrack) return false;
	return reasm_feed(ctrack, &ctrack->reasm_client, proto, (proto == IPPROTO_TCP) ? ctrack->pos.client.seq_last : (uint32_t)ctrack->reasm_client.size_present, data_payload, len_payload);
}
static void reasm_client_stop(t_ctrack *ctrack, const char *dlog_msg)
{
	if (ctrack)
	{
		if (!ReasmIsEmpty(&ctrack->reasm_client))
		{
			DLOG("%s", dlog_msg);
			ReasmClear(&ctrack->reasm_client);
			ctrack->reasm_client_payload = L7P_UNKNOWN;
		}
		send_delayed(ctrack);
	}
}
static void reasm_client_cancel(t_ctrack *ctrack)
{
	reasm_client_stop(ctrack, "reassemble session cancelled\n");
}
static void reasm_client_fin(t_ctrack *ctrack)
{
	reasm_client_stop(ctrack, "reassemble session finished\n");
}


static uint8_t ct_new_postnat_fix(const t_ctrack *ctrack, const struct dissect *dis, uint8_t *mod_pkt, size_t *len_mod_pkt)
{
#ifdef __linux__
	// if used in postnat chain, dropping initial packet will cause conntrack connection teardown
	// so we need to workaround this.
	// SYN and SYN,ACK checks are for conntrack-less mode
	if ((ctrack && (params.server ? ctrack->pos.server.pcounter : ctrack->pos.client.pcounter) == 1) ||
		(!ctrack && dis->tcp && (tcp_syn_segment(dis->tcp) || tcp_synack_segment(dis->tcp))))
	{
		if (dis->len_pkt > *len_mod_pkt)
			DLOG_ERR("linux postnat conntrack workaround cannot be applied\n");
		else
		{
			memcpy(mod_pkt, dis->data_pkt, dis->len_pkt);
			DLOG("applying linux postnat conntrack workaround\n");
			// make ip protocol invalid and low TTL
			if (dis->ip6)
			{
				((struct ip6_hdr*)mod_pkt)->ip6_ctlun.ip6_un1.ip6_un1_nxt = 255;
				((struct ip6_hdr*)mod_pkt)->ip6_ctlun.ip6_un1.ip6_un1_hlim = 1;
			}
			if (dis->ip)
			{
				// this likely also makes ipv4 header checksum invalid
				((struct ip*)mod_pkt)->ip_p = 255;
				((struct ip*)mod_pkt)->ip_ttl = 1;
			}
			*len_mod_pkt = dis->len_pkt;
			return VERDICT_MODIFY | VERDICT_NOCSUM;
		}
	}
#endif
	return VERDICT_DROP;
}

static bool pos_overflow(const t_ctrack_position *pos, char mode)
{
	return (mode=='s' || mode=='p') && pos && pos->rseq_over_2G;
}
static uint64_t pos_get(const t_ctrack_position *pos, char mode)
{
	if (pos)
	{
		switch (mode)
		{
		case 'n': return pos->pcounter;
		case 'd': return pos->pdcounter;
		case 's': return pos->seq_last - pos->seq0;
		case 'p': return pos->pos - pos->seq0;
		case 'b': return pos->pbcounter;
		}
	}
	return 0;
}
static bool check_pos_from(const t_ctrack_position *pos, const struct packet_range *range)
{
	uint64_t ps;
	if ((range->from.mode == 'x') || pos_overflow(pos,range->from.mode)) return false;
	if (range->from.mode != 'a')
	{
		if (pos)
		{
			ps = pos_get(pos, range->from.mode);
			return ps >= range->from.pos;
		}
		else
			return false;
	}
	return true;
}
static bool check_pos_to(const t_ctrack_position *pos, const struct packet_range *range)
{
	uint64_t ps;
	if (range->to.mode == 'x' || pos_overflow(pos,range->to.mode)) return false;
	if (range->to.mode != 'a')
	{
		if (pos)
		{
			ps = pos_get(pos, range->to.mode);
			return (ps < range->to.pos) || (!range->upper_cutoff && (ps == range->to.pos));
		}
		else
			return false;
	}
	return true;
}
static bool check_pos_cutoff(const t_ctrack_position *pos, const struct packet_range *range)
{
	bool bto = check_pos_to(pos, range);
	return pos ? !bto : (!bto || !check_pos_from(pos, range));
}
static bool check_pos_range(const t_ctrack_position *pos, const struct packet_range *range)
{
	return check_pos_from(pos, range) && check_pos_to(pos, range);
}


static bool replay_queue(struct rawpacket_tailhead *q);

static bool ipcache_put_hostname(const struct in_addr *a4, const struct in6_addr *a6, const char *hostname, bool hostname_is_ip)
{
	if (!params.cache_hostname) return true;

	ip_cache_item *ipc = ipcacheTouch(&params.ipcache, a4, a6, NULL);
	if (!ipc)
	{
		DLOG_ERR("ipcache_put_hostname: out of memory\n");
		return false;
	}
	if (!ipc->hostname || strcmp(ipc->hostname, hostname))
	{
		free(ipc->hostname);
		if (!(ipc->hostname = strdup(hostname)))
		{
			DLOG_ERR("ipcache_put_hostname: out of memory\n");
			return false;
		}
		ipc->hostname_is_ip = hostname_is_ip;
		DLOG("hostname cached (is_ip=%u): %s\n", hostname_is_ip, hostname);
	}
	return true;
}
static bool ipcache_get_hostname(const struct in_addr *a4, const struct in6_addr *a6, char *hostname, size_t hostname_buf_len, bool *hostname_is_ip)
{
	if (!params.cache_hostname)
	{
		*hostname = 0;
		return false;
	}
	if (params.debug)
	{
		char s[INET6_ADDRSTRLEN];
		ntopa46(a4, a6, s, sizeof(s));
		DLOG("ipcache hostname search for %s\n", s);
	}
	ip_cache_item *ipc = ipcacheFind(&params.ipcache, a4, a6, NULL);
	if (ipc && ipc->hostname)
	{
		if (params.debug)
		{
			char s[INET6_ADDRSTRLEN];
			ntopa46(a4, a6, s, sizeof(s));
			DLOG("got cached hostname for %s : %s (is_ip=%u)\n", s, ipc->hostname, ipc->hostname_is_ip);
		}
		snprintf(hostname, hostname_buf_len, "%s", ipc->hostname);
		if (hostname_is_ip) *hostname_is_ip = ipc->hostname_is_ip;
	}
	else
		*hostname = 0;
	return *hostname;
}
static void ipcache_update_ttl(t_ctrack *ctrack, const struct in_addr *a4, const struct in6_addr *a6, const char *iface)
{
	// no need to cache ttl in server mode because first packet is incoming
	if (ctrack && !params.server)
	{
		ip_cache_item *ipc;
		if (ctrack->incoming_ttl)
		{
			ipc = ipcacheTouch(&params.ipcache, a4, a6, iface);
			if (!ipc)
			{
				DLOG_ERR("ipcache: out of memory\n");
				return;
			}
			if (ipc->ttl != ctrack->incoming_ttl)
			{
				DLOG("updated ttl cache\n");
				ipc->ttl = ctrack->incoming_ttl;
			}
		}
		else
		{
			ipc = ipcacheFind(&params.ipcache, a4, a6, iface);
			if (ipc && ipc->ttl)
			{
				DLOG("got cached ttl %u\n", ipc->ttl);
				ctrack->incoming_ttl = ipc->ttl;
			}
		}
	}
}
static void ipcache_get_ttl(t_ctrack *ctrack, const struct in_addr *a4, const struct in6_addr *a6, const char *iface)
{
	// no need to cache ttl in server mode because first packet is incoming
	if (ctrack && !ctrack->incoming_ttl && !params.server)
	{
		ip_cache_item *ipc = ipcacheFind(&params.ipcache, a4, a6, iface);
		if (ipc && ipc->ttl)
		{
			DLOG("got cached ttl %u\n", ipc->ttl);
			ctrack->incoming_ttl = ipc->ttl;
		}
	}
}



static bool desync_get_result(uint8_t *verdict)
{
	int rescount = lua_gettop(params.L);
	if (rescount>1)
	{
		DLOG_ERR("desync function returned more than one result : %d\n", rescount);
		goto err;
	}
	if (rescount)
	{
		if (!lua_isinteger(params.L, -1))
		{
			DLOG_ERR("desync function returned non-int result\n");
			goto err;
		}
		lua_Integer lv = lua_tointeger(params.L, -1);
		if (lv & ~VERDICT_MASK_VALID_LUA)
		{
			DLOG_ERR("desync function returned bad int result\n");
			goto err;
		}
		*verdict = (uint8_t)lv;
	}
	else
		*verdict = VERDICT_PASS; // default result if function returns nothing
	lua_pop(params.L, rescount);
	return true;
err:
	lua_pop(params.L, rescount);
	return false;
}
static uint8_t verdict_aggregate(uint8_t v1,uint8_t v2)
{
	uint8_t verdict_action = v1 & VERDICT_MASK;
	switch (v2 & VERDICT_MASK)
	{
		case VERDICT_MODIFY:
			if (verdict_action == VERDICT_PASS) verdict_action = VERDICT_MODIFY;
			break;
		case VERDICT_DROP:
			verdict_action = VERDICT_DROP;
			break;
	}
	return v1 & ~VERDICT_MASK | verdict_action | v2 & VERDICT_PRESERVE_NEXT;
}
static uint8_t desync(
	struct desync_profile *dp,
	uint32_t fwmark,
	const char *ifin,
	const char *ifout,
	bool bIncoming,
	t_ctrack *ctrack,
	const t_ctrack_positions *tpos,
	t_l7payload l7payload,
	t_l7proto l7proto,
	const struct dissect *dis,
	const struct in_addr *sdp4, const struct in6_addr *sdp6, uint16_t sdport,
	uint8_t *mod_pkt, size_t *len_mod_pkt,
	unsigned int replay_piece, unsigned int replay_piece_count, size_t reasm_offset, const uint8_t *rdata_payload, size_t rlen_payload,
	const uint8_t *data_decrypt, size_t len_decrypt)
{
	uint8_t verdict = VERDICT_PASS, verdict_func;
	struct func_list *func;
	int ref_arg = LUA_NOREF, status;
	bool b, b_cutoff_all, b_unwanted_payload;
	const char *sDirection = bIncoming ? "in" : "out";
	struct packet_range *range;
	size_t l;
	char instance[256];
	const t_ctrack_position *pos, *rpos;

	if (ctrack)
	{
		// fast way not to do anything
		if (bIncoming && ctrack->b_lua_in_cutoff)
		{
			DLOG("lua in cutoff\n");
			return verdict;
		}
		if (!bIncoming && ctrack->b_lua_out_cutoff)
		{
			DLOG("lua out cutoff\n");
			return verdict;
		}
		if (!tpos) tpos = &ctrack->pos;
	}
	pos = tpos ? (bIncoming ^ params.server) ? &tpos->server : &tpos->client : NULL;
	rpos = tpos ? (bIncoming ^ params.server) ? &tpos->client : &tpos->server : NULL;

	LUA_STACK_GUARD_ENTER(params.L)

	if (LIST_FIRST(&dp->lua_desync))
	{
		lua_rawgeti(params.L, LUA_REGISTRYINDEX, params.ref_desync_ctx);
		t_lua_desync_context *ctx = (t_lua_desync_context *)luaL_checkudata(params.L, -1, "desync_ctx");
		// this is singleton stored in the registry. safe to pop
		lua_pop(params.L,1);

		ctx->dp = dp;
		ctx->ctrack = ctrack;
		ctx->dis = dis;
		ctx->cancel = false;
		ctx->incoming = bIncoming;

		b_cutoff_all = b_unwanted_payload = true;
		ctx->func_n = 1;
		LIST_FOREACH(func, &dp->lua_desync, next)
		{
			ctx->func = func->func;
			desync_instance(func->func, dp->n, ctx->func_n, instance, sizeof(instance));
			ctx->instance = instance;
			range = bIncoming ? &func->range_in : &func->range_out;

			if (b_unwanted_payload)
				b_unwanted_payload &= !l7_payload_match(l7payload, func->payload_type);

			if (b_cutoff_all)
			{
				if (lua_instance_cutoff_check(params.L, ctx, bIncoming))
					DLOG("* lua '%s' : voluntary cutoff\n", instance);
				else if (check_pos_cutoff(pos, range))
				{
					DLOG("* lua '%s' : %s pos %c%llu %c%llu overflow %u %u is beyond range %c%u%c%c%u (ctrack %s)\n",
						instance, sDirection,
						range->from.mode, pos_get(pos, range->from.mode),
						range->to.mode, pos_get(pos, range->to.mode),
						pos_overflow(pos, range->from.mode),
						pos_overflow(pos, range->to.mode),
						range->from.mode, range->from.pos,
						range->upper_cutoff ? '<' : '-',
						range->to.mode, range->to.pos,
						ctrack ? "enabled" : "disabled");
				}
				else
					b_cutoff_all = false;
			}
			ctx->func_n++;
		}
		if (b_cutoff_all)
		{
			DLOG("all %s desync functions reached cutoff condition\n", sDirection);
			if (ctrack) *(bIncoming ? &ctrack->b_lua_in_cutoff : &ctrack->b_lua_out_cutoff) = true;
		}
		else if (b_unwanted_payload)
			DLOG("all %s desync functions do not want `%s` payload\n", sDirection, l7payload_str(l7payload));
		else
		{
			// create arg table that persists across multiple desync function calls
			lua_newtable(params.L);
			lua_pushf_dissect(params.L, dis);
			lua_pushf_ctrack(params.L, ctrack, tpos, bIncoming);
			lua_pushf_int(params.L, "profile_n", dp->n);
			if (dp->name) lua_pushf_str(params.L, "profile_name", dp->name);
			if (dp->cookie) lua_pushf_str(params.L, "cookie", dp->cookie);
			lua_pushf_bool(params.L, "outgoing", !bIncoming);
			lua_pushf_str(params.L, "ifin", (ifin && *ifin) ? ifin : NULL);
			lua_pushf_str(params.L, "ifout", (ifout && *ifout) ? ifout : NULL);
			lua_pushf_lint(params.L, "fwmark", fwmark);
			lua_pushf_table(params.L, "target");
			lua_getfield(params.L,-1,"target");
			if (sdport) lua_pushf_int(params.L, "port",sdport);
			if (sdp4) lua_pushf_lstr(params.L, "ip",(const char*)sdp4,sizeof(*sdp4));
			if (sdp6) lua_pushf_lstr(params.L, "ip6",(const char*)sdp6,sizeof(*sdp6));
			lua_pop(params.L,1);
			lua_pushf_bool(params.L, "replay", !!replay_piece_count);
			if (replay_piece_count)
			{
				lua_pushf_int(params.L, "replay_piece", replay_piece+1);
				lua_pushf_int(params.L, "replay_piece_count", replay_piece_count);
				lua_pushf_bool(params.L, "replay_piece_last", (replay_piece+1)>=replay_piece_count);
			}
			lua_pushf_str(params.L, "l7payload", l7payload_str(l7payload));
			lua_pushf_str(params.L, "l7proto", l7proto_str(l7proto));
			lua_pushf_int(params.L, "reasm_offset", reasm_offset);
			lua_pushf_raw(params.L, "reasm_data", rdata_payload, rlen_payload);
			lua_pushf_raw(params.L, "decrypt_data", data_decrypt, len_decrypt);
			//if (ctrack) lua_pushf_reg("instance_cutoff", ctrack->lua_instance_cutoff);
			if (dis->tcp)
			{
				// recommended mss value for generated packets
				if (pos && pos->mss && rpos && rpos->mss)
					// use minimum MSS of two ends or can fail with "message too long"
					lua_pushf_int(params.L, "tcp_mss", rpos->mss > pos->mss ? pos->mss : rpos->mss);
				else
					// this value should always work
					lua_pushf_global(params.L, "tcp_mss", "DEFAULT_MSS");
			}
			ref_arg = luaL_ref(params.L, LUA_REGISTRYINDEX);

			ctx->func_n = 1;
			LIST_FOREACH(func, &dp->lua_desync, next)
			{
				ctx->func = func->func;
				desync_instance(func->func, dp->n, ctx->func_n, instance, sizeof(instance));
				ctx->instance = instance;

				if (!lua_instance_cutoff_check(params.L, ctx, bIncoming))
				{
					range = bIncoming ? &func->range_in : &func->range_out;
					if (check_pos_range(pos, range))
					{
						DLOG("* lua '%s' : %s pos %c%llu %c%llu in range %c%u%c%c%u\n",
							instance, sDirection,
							range->from.mode, pos_get(pos, range->from.mode),
							range->to.mode, pos_get(pos, range->to.mode),
							range->from.mode, range->from.pos,
							range->upper_cutoff ? '<' : '-',
							range->to.mode, range->to.pos);
						if (l7_payload_match(l7payload, func->payload_type))
						{
							DLOG("* lua '%s' : payload_type '%s' satisfy filter\n", instance, l7payload_str(l7payload));
							DLOG("* lua '%s' : desync\n", instance);
							lua_getglobal(params.L, func->func);
							if (!lua_isfunction(params.L, -1))
							{
								lua_pop(params.L, 1);
								DLOG_ERR("desync function '%s' does not exist\n", func->func);
								goto err;
							}
							lua_rawgeti(params.L, LUA_REGISTRYINDEX, params.ref_desync_ctx);
							lua_rawgeti(params.L, LUA_REGISTRYINDEX, ref_arg);
							lua_pushf_args(params.L, &func->args, -1, true);
							lua_pushf_str(params.L, "func", func->func);
							lua_pushf_int(params.L, "func_n", ctx->func_n);
							lua_pushf_str(params.L, "func_instance", instance);

							// prevent use of desync ctx object outside of function call
							ctx->valid = true;
							status = lua_pcall(params.L, 2, LUA_MULTRET, 0);
							ctx->valid = false;

							if (status)
							{
								lua_dlog_error();
								goto err;
							}
							if (!desync_get_result(&verdict_func))
								goto err;

							verdict = verdict_aggregate(verdict, verdict_func);
						}
						else
							DLOG("* lua '%s' : payload_type '%s' does not satisfy filter\n", instance, l7payload_str(l7payload));
					}
					else
						DLOG("* lua '%s' : %s pos %c%llu %c%llu out of range %c%u%c%c%u\n",
							instance, sDirection,
							range->from.mode, pos_get(pos, range->from.mode),
							range->to.mode, pos_get(pos, range->to.mode),
							range->from.mode, range->from.pos,
							range->upper_cutoff ? '<' : '-',
							range->to.mode, range->to.pos);
				}
				if (ctx->cancel) break;
				ctx->func_n++;
			}
		}

		if ((verdict & VERDICT_MASK)==VERDICT_MODIFY)
		{
			// use same memory buffer to reduce memory copying
			// packet size cannot grow
			sockaddr_in46 sa;

			lua_rawgeti(params.L, LUA_REGISTRYINDEX, ref_arg);
			lua_getfield(params.L, -1, "dis");
			if (lua_type(params.L, -1) != LUA_TTABLE)
			{
				lua_pop(params.L, 2);
				DLOG_ERR("dissect data is bad. VERDICT_MODIFY cancel.\n");
				goto err;
			}
			else
			{
				b = lua_reconstruct_dissect(params.L, -1, mod_pkt, len_mod_pkt, false, false, IPPROTO_NONE, !!(verdict & VERDICT_PRESERVE_NEXT));
				lua_pop(params.L, 2);
				if (!b)
				{
					DLOG_ERR("failed to reconstruct packet after VERDICT_MODIFY\n");
					verdict = VERDICT_PASS;
					goto ex;
				}
				DLOG("reconstructed packet due to VERDICT_MODIFY. size %zu => %zu\n", dis->len_pkt, *len_mod_pkt);
				// no need to recalc sum after reconstruct
				verdict |= VERDICT_NOCSUM;
			}
		}
	}
	else
		DLOG("no lua functions in this profile\n");
ex:
	luaL_unref(params.L, LUA_REGISTRYINDEX, ref_arg);
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return verdict;
err:
	DLOG_ERR("desync ERROR. passing packet unmodified.\n");
	// do not do anything with the packet on error
	verdict = VERDICT_PASS;
	goto ex;
}



static void setup_direction(
	const struct dissect *dis,
	bool bReverseFixed,
	struct sockaddr_storage *src,
	struct sockaddr_storage *dst,
	const struct in_addr **sdip4,
	const struct in6_addr **sdip6,
	uint16_t *sdport)
{
	extract_endpoints(dis->ip, dis->ip6, dis->tcp, dis->udp, src, dst);
	if (dis->ip6)
	{
		*sdip4 = NULL;
		*sdip6 = bReverseFixed ? &dis->ip6->ip6_src : &dis->ip6->ip6_dst;
	}
	else if (dis->ip)
	{
		*sdip6 = NULL;
		*sdip4 = bReverseFixed ? &dis->ip->ip_src : &dis->ip->ip_dst;
	}
	else
	{
		// should never happen
		*sdip6 = NULL; *sdip4 = NULL; *sdport = 0;
		return;
	}
	*sdport = saport((struct sockaddr *)((bReverseFixed ^ params.server) ? src : dst));

	if (params.debug)
	{
		char ip[INET6_ADDRSTRLEN];
		ntopa46(*sdip4, *sdip6, ip, sizeof(ip));
		DLOG("%s mode desync profile/ipcache search target ip=%s port=%u\n", params.server ? "server" : "client", ip, *sdport);
	}
}

static void dp_changed(t_ctrack *ctrack)
{
	if (ctrack)
	{
		if (ctrack->b_lua_in_cutoff)
		{
			DLOG("clearing lua in cutoff because of profile change\n");
			ctrack->b_lua_in_cutoff = false;
		}
		if (ctrack->b_lua_out_cutoff)
		{
			DLOG("clearing lua out cutoff because of profile change\n");
			ctrack->b_lua_out_cutoff = false;
		}
	}
}


struct play_state
{
	const struct dissect *dis;
	struct desync_profile *dp;
	const t_ctrack_positions *tpos;
	t_ctrack *ctrack, *ctrack_replay;
	struct sockaddr_storage src, dst;
	const struct in_addr *sdip4;
	const struct in6_addr *sdip6;
	uint16_t sdport;
	uint8_t verdict;
	char host[256];
	t_l7proto l7proto;
	t_l7payload l7payload;
	const char *ssid;
	bool bReverse, bReverseFixed, bHaveHost;
};
static bool play_prolog(
	struct play_state *ps,
	const struct dissect *dis,
	const t_ctrack_positions *tpos,
	bool bReplay,
	const char *ifin, const char *ifout)
{
	ps->verdict = VERDICT_PASS;

	// additional safety check
	if (!!dis->ip == !!dis->ip6) return false;

	ps->dis = dis;
	ps->tpos = tpos;
	ps->dp = NULL;
	ps->ctrack = ps->ctrack_replay = NULL;
	ps->bReverse = ps->bReverseFixed = ps->bHaveHost = false;
	ps->l7proto = L7_UNKNOWN;
	ps->l7payload = dis->len_payload ? L7P_UNKNOWN : L7P_EMPTY;
	ps->ssid = NULL;

	const char *ifname;

	if (bReplay)
	{
		// in replay mode conntrack_replay is not NULL and ctrack is NULL

		//ConntrackPoolDump(&params.conntrack);
		if (!ConntrackPoolDoubleSearch(&params.conntrack, dis, &ps->ctrack_replay, &ps->bReverse) || ps->bReverse)
			return false;
		ps->bReverseFixed = ps->bReverse ^ params.server;
		setup_direction(dis, ps->bReverseFixed, &ps->src, &ps->dst, &ps->sdip4, &ps->sdip6, &ps->sdport);
		ifname = ps->bReverseFixed ? ifin : ifout;
#ifdef HAS_FILTER_SSID
		ps->ssid = wlan_ssid_search_ifname(ifname);
		if (ps->ssid) DLOG("found ssid for %s : %s\n", ifname, ps->ssid);
#endif
		ps->l7proto = ps->ctrack_replay->l7proto;
		ps->dp = ps->ctrack_replay->dp;
		if (ps->dp)
			DLOG("using cached desync profile %u (%s)\n", ps->dp->n, PROFILE_NAME(ps->dp));
		else if (!ps->ctrack_replay->dp_search_complete)
		{
			ps->dp = ps->ctrack_replay->dp = dp_find(&params.desync_profiles, dis->proto, ps->sdip4, ps->sdip6, NULL, NULL, ps->sdport, 0xFF, 0xFF, ps->ctrack_replay->hostname, ps->ctrack_replay->hostname_is_ip, ps->l7proto, ps->ssid, NULL, NULL, NULL);
			ps->ctrack_replay->dp_search_complete = true;
		}
		if (!ps->dp)
		{
			DLOG("matching desync profile not found\n");
			return false;
		}
	}
	else
	{
		// in real mode ctrack may be NULL or not NULL, conntrack_replay is equal to ctrack

		if (!params.ctrack_disable)
		{
			ConntrackPoolPurge(&params.conntrack);
			if (ConntrackPoolFeed(&params.conntrack, dis, &ps->ctrack, &ps->bReverse))
			{
				ps->dp = ps->ctrack->dp;
				ps->ctrack_replay = ps->ctrack;
			}
		}
		// in absence of conntrack guess direction by presence of interface names. won't work on BSD
		ps->bReverseFixed = ps->ctrack ? (ps->bReverse ^ params.server) : (ps->bReverse = ifin && *ifin && (!ifout || !*ifout));
		setup_direction(dis, ps->bReverseFixed, &ps->src, &ps->dst, &ps->sdip4, &ps->sdip6, &ps->sdport);
		ifname = ps->bReverseFixed ? ifin : ifout;
#ifdef HAS_FILTER_SSID
		ps->ssid = wlan_ssid_search_ifname(ifname);
		if (ps->ssid) DLOG("found ssid for %s : %s\n", ifname, ps->ssid);
#endif
		if (ps->ctrack) ps->l7proto = ps->ctrack->l7proto;
		if (ps->dp)
			DLOG("using cached desync profile %u (%s)\n", ps->dp->n, PROFILE_NAME(ps->dp));
		else if (!ps->ctrack || !ps->ctrack->dp_search_complete)
		{
			const char *hostname = NULL;
			bool hostname_is_ip = false;
			if (ps->ctrack)
			{
				hostname = ps->ctrack->hostname;
				hostname_is_ip = ps->ctrack->hostname_is_ip;
				if (!hostname && !ps->bReverse)
				{
					if (ipcache_get_hostname(ps->sdip4, ps->sdip6, ps->host, sizeof(ps->host), &hostname_is_ip))
						if (!(hostname = ps->ctrack->hostname = strdup(ps->host)))
							DLOG_ERR("strdup(host): out of memory\n");
				}
			}
			ps->dp = dp_find(&params.desync_profiles, dis->proto, ps->sdip4, ps->sdip6, NULL, NULL, ps->sdport, 0xFF, 0xFF, hostname, hostname_is_ip, ps->l7proto, ps->ssid, NULL, NULL, NULL);
			if (ps->ctrack)
			{
				ps->ctrack->dp = ps->dp;
				ps->ctrack->dp_search_complete = true;
			}
		}
		if (!ps->dp)
		{
			DLOG("matching desync profile not found\n");
			return false;
		}

		HostFailPoolPurgeRateLimited(&ps->dp->hostlist_auto_fail_counters, &ps->dp->hostlist_auto_last_purge);
		//ConntrackPoolDump(&params.conntrack);

		if (ps->bReverseFixed)
		{
			if (ps->ctrack && !ps->ctrack->incoming_ttl)
			{
				ps->ctrack->incoming_ttl = ttl46(dis->ip, dis->ip6);
				DLOG("incoming TTL %u\n", ps->ctrack->incoming_ttl);
			}
			ipcache_update_ttl(ps->ctrack, ps->sdip4, ps->sdip6, ifin);
		}
		else
			ipcache_get_ttl(ps->ctrack, ps->sdip4, ps->sdip6, ifout);
	} // !replay

	if (!tpos && ps->ctrack_replay) ps->tpos=&ps->ctrack_replay->pos;

	return true;
}
static bool dp_rediscovery(struct play_state *ps)
{
	bool bHostIsIp = false;

	if (ps->bHaveHost)
	{
		bHostIsIp = strip_host_to_ip(ps->host);
		DLOG("hostname: %s\n", ps->host);
	}

	bool bDiscoveredL7;
	if (ps->ctrack_replay)
	{
		if ((bDiscoveredL7 = !ps->ctrack_replay->l7proto_discovered && ps->ctrack_replay->l7proto != L7_UNKNOWN))
			ps->ctrack_replay->l7proto_discovered = true;
	}
	else
		bDiscoveredL7 = ps->l7proto != L7_UNKNOWN;
	if (bDiscoveredL7) DLOG("discovered l7 protocol\n");

	bool bDiscoveredHostname = ps->bHaveHost && !(ps->ctrack_replay && ps->ctrack_replay->hostname_discovered);
	if (bDiscoveredHostname)
	{
		DLOG("discovered hostname\n");
		if (ps->ctrack_replay)
		{
			free(ps->ctrack_replay->hostname);
			ps->ctrack_replay->hostname = strdup(ps->host);
			ps->ctrack_replay->hostname_is_ip = bHostIsIp;
			if (!ps->ctrack_replay->hostname)
			{
				DLOG_ERR("hostname dup : out of memory");
				return false;
			}
			ps->ctrack_replay->hostname_discovered = true;
			if (!ipcache_put_hostname(ps->sdip4, ps->sdip6, ps->host, bHostIsIp))
				return false;
		}
	}
	bool bCheckDone, bCheckResult, bCheckExcluded;
	if (ps->ctrack_replay)
	{
		bCheckDone = ps->ctrack_replay->bCheckDone;
		bCheckResult = ps->ctrack_replay->bCheckResult;
		bCheckExcluded = ps->ctrack_replay->bCheckExcluded;
	}
	else
		bCheckDone = bCheckResult = bCheckExcluded = false;
	if (bDiscoveredL7 || bDiscoveredHostname)
	{
		struct desync_profile *dp_prev = ps->dp;
		// search for desync profile again. it may have changed.
		ps->dp = dp_find(&params.desync_profiles, ps->dis->proto, ps->sdip4, ps->sdip6, NULL, NULL, ps->sdport, 0xFF, 0xFF,
			ps->ctrack_replay ? ps->ctrack_replay->hostname : ps->bHaveHost ? ps->host : NULL,
			ps->ctrack_replay ? ps->ctrack_replay->hostname_is_ip : bHostIsIp,
			ps->l7proto, ps->ssid,
			&bCheckDone, &bCheckResult, &bCheckExcluded);
		if (ps->ctrack_replay)
		{
			ps->ctrack_replay->dp = ps->dp;
			ps->ctrack_replay->dp_search_complete = true;
			ps->ctrack_replay->bCheckDone = bCheckDone;
			ps->ctrack_replay->bCheckResult = bCheckResult;
			ps->ctrack_replay->bCheckExcluded = bCheckExcluded;
		}
		if (!ps->dp) return false;
		if (ps->dp != dp_prev)
		{
			dp_changed(ps->ctrack_replay);
			DLOG("desync profile changed by revealed l7 protocol or hostname !\n");
		}
	}
	if (ps->bHaveHost && !PROFILE_HOSTLISTS_EMPTY(ps->dp))
	{
		if (!bCheckDone)
		{
			bCheckResult = HostlistCheck(ps->dp, ps->host, bHostIsIp, &bCheckExcluded, false);
			bCheckDone = true;
			if (ps->ctrack_replay)
			{
				ps->ctrack_replay->bCheckDone = bCheckDone;
				ps->ctrack_replay->bCheckResult = bCheckResult;
				ps->ctrack_replay->bCheckExcluded = bCheckExcluded;
			}
		}
		if (ps->ctrack_replay)
		{
			if (bCheckResult)
			{
				if (ps->dis->proto==IPPROTO_TCP)
					ctrack_stop_retrans_counter(ps->ctrack_replay);
			}
			else
			{
				ps->ctrack_replay->hostname_ah_check = ps->dp->hostlist_auto && !bCheckExcluded;
				if (ps->dis->proto==IPPROTO_TCP && !ps->ctrack_replay->hostname_ah_check)
					ctrack_stop_retrans_counter(ps->ctrack_replay);
			}
		}
	}

	if (ps->ctrack_replay && ps->dis->proto==IPPROTO_UDP)
		process_udp_fail(ps->ctrack_replay, ps->tpos, (struct sockaddr*)&ps->src);

	if (bCheckDone && !bCheckResult)
	{
		DLOG("not applying tampering because of previous negative hostlist check\n");
		return false;
	}

	if (params.debug)
	{
		char s1[48], s2[48];
		ntop46_port((struct sockaddr *)&ps->src, s1, sizeof(s1));
		ntop46_port((struct sockaddr *)&ps->dst, s2, sizeof(s2));
		DLOG("dpi desync src=%s dst=%s track_direction=%s fixed_direction=%s connection_proto=%s payload_type=%s\n",
			s1, s2, ps->bReverse ? "in" : "out", ps->bReverseFixed ? "in" : "out", l7proto_str(ps->l7proto), l7payload_str(ps->l7payload));
	}

	return true;
}


static uint8_t dpi_desync_tcp_packet_play(
	unsigned int replay_piece, unsigned int replay_piece_count, size_t reasm_offset,
	uint32_t fwmark,
	const char *ifin, const char *ifout,
	const t_ctrack_positions *tpos,
	const struct dissect *dis,
	uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	struct play_state ps;

	if (!play_prolog(&ps, dis, tpos, !!replay_piece_count, ifin, ifout))
		return ps.verdict;

	uint32_t desync_fwmark = fwmark | params.desync_fwmark;
	const uint8_t *rdata_payload = dis->data_payload;
	size_t rlen_payload = dis->len_payload;

	if (ps.bReverse)
	{
		// protocol detection
		if (!(dis->tcp->th_flags & TH_SYN) && dis->len_payload)
		{
			t_protocol_probe testers[] = {
				{L7P_TLS_SERVER_HELLO,L7_TLS,IsTLSServerHelloPartial,false},
				{L7P_HTTP_REPLY,L7_HTTP,IsHttpReply,false},
				{L7P_XMPP_STREAM,L7_XMPP,IsXMPPStream,false},
				{L7P_XMPP_PROCEED,L7_XMPP,IsXMPPProceedTLS,false},
				{L7P_XMPP_FEATURES,L7_XMPP,IsXMPPFeatures,false},
				{L7P_BT_HANDSHAKE,L7_BT,IsBTHandshake,false}
			};
			protocol_probe(testers, sizeof(testers) / sizeof(*testers), dis->data_payload, dis->len_payload, ps.ctrack, &ps.l7proto, &ps.l7payload);

			if (ps.l7payload==L7P_TLS_SERVER_HELLO)
				TLSDebug(dis->data_payload, dis->len_payload);
		}

		// process reply packets for auto hostlist mode
		// by looking at RSTs or HTTP replies we decide whether original request looks like DPI blocked
		// we only process first-sequence replies. do not react to subsequent redirects or RSTs
		if (!params.server && ps.ctrack && ps.ctrack->hostname_ah_check && !ps.ctrack->failure_detect_finalized && ps.dp->hostlist_auto_incoming_maxseq)
		{
			uint32_t rseq = ps.ctrack->pos.server.seq_last - ps.ctrack->pos.server.seq0;
			if (rseq)
			{
				char client_ip_port[48];
				fill_client_ip_port((struct sockaddr*)&ps.dst, client_ip_port, sizeof(client_ip_port));
				if (seq_within(ps.ctrack->pos.server.seq_last, ps.ctrack->pos.server.seq0 + 1, ps.ctrack->pos.server.seq0 + ps.dp->hostlist_auto_incoming_maxseq))
				{
					bool bFail = false;

					if (ps.dis->tcp->th_flags & TH_RST)
					{
						DLOG("incoming RST detected for hostname %s rseq %u\n", ps.ctrack->hostname, rseq);
						HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : rseq %u : incoming RST", ps.ctrack->hostname, ps.ctrack->dp->n, PROFILE_NAME(ps.dp), client_ip_port, l7proto_str(ps.l7proto), rseq);
						bFail = true;
					}
					else if (dis->len_payload && ps.l7payload == L7P_HTTP_REPLY)
					{
						DLOG("incoming HTTP reply detected for hostname %s rseq %u\n", ps.ctrack->hostname, rseq);
						bFail = HttpReplyLooksLikeDPIRedirect(dis->data_payload, dis->len_payload, ps.ctrack->hostname);
						if (bFail)
						{
							DLOG("redirect to another domain detected. possibly DPI redirect.\n");
							HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : rseq %u : redirect to another domain", ps.ctrack->hostname, ps.ctrack->dp->n, PROFILE_NAME(ps.dp), client_ip_port, l7proto_str(ps.l7proto), rseq);
						}
						else
							DLOG("local or in-domain redirect detected. it's not a DPI redirect.\n");
					}
					if (bFail)
					{
						auto_hostlist_failed(ps.dp, ps.ctrack->hostname, ps.ctrack->hostname_is_ip, client_ip_port, ps.l7proto);
						ps.ctrack->failure_detect_finalized = true;
					}
				}
				else
				{
					// incoming_maxseq exceeded. treat connection as successful
					DLOG("incoming rseq %u > %u\n",rseq,ps.dp->hostlist_auto_incoming_maxseq);
					auto_hostlist_reset_fail_counter(ps.dp, ps.ctrack->hostname, client_ip_port, ps.l7proto);
					ps.ctrack->failure_detect_finalized = true;
				}
			}
		}
	}
	// not reverse
	else if (!(dis->tcp->th_flags & TH_SYN) && dis->len_payload)
	{
		struct blob_collection_head *fake;
		uint8_t *p, *phost = NULL;
		int i;

		if (replay_piece_count)
		{
			rdata_payload = ps.ctrack_replay->reasm_client.packet;
			rlen_payload = ps.ctrack_replay->reasm_client.size_present;
		}
		else if (reasm_client_feed(ps.ctrack, IPPROTO_TCP, dis->data_payload, dis->len_payload))
		{
			rdata_payload = ps.ctrack->reasm_client.packet;
			rlen_payload = ps.ctrack->reasm_client.size_present;
		}

		process_retrans_fail(ps.ctrack, dis, (struct sockaddr*)&ps.src, ifin);

		// do not detect payload if reasm is in progress
		if (!ps.ctrack_replay || ReasmIsEmpty(&ps.ctrack_replay->reasm_client))
		{
			t_protocol_probe testers[] = {
				{L7P_TLS_CLIENT_HELLO,L7_TLS,IsTLSClientHelloPartial,false},
				{L7P_HTTP_REQ,L7_HTTP,IsHttp,false},
				{L7P_XMPP_STREAM,L7_XMPP,IsXMPPStream,false},
				{L7P_XMPP_STARTTLS,L7_XMPP,IsXMPPStartTLS,false},
				{L7P_BT_HANDSHAKE,L7_BT,IsBTHandshake,false}
			};
			protocol_probe(testers, sizeof(testers) / sizeof(*testers), rdata_payload, rlen_payload, ps.ctrack_replay, &ps.l7proto, &ps.l7payload);

			if (ps.l7payload==L7P_UNKNOWN)
			{
				// this is special type. detection requires AES and can be successful only for the first data packet. no reason to AES every packet
				if (ps.tpos && (ps.tpos->client.seq_last - ps.tpos->client.seq0)==1)
				{
					t_protocol_probe testers[] = {
						{L7P_MTPROTO_INITIAL,L7_MTPROTO,IsMTProto,false}
					};
					protocol_probe(testers, sizeof(testers) / sizeof(*testers), rdata_payload, rlen_payload, ps.ctrack_replay, &ps.l7proto, &ps.l7payload);
				}
			}
		}
		if (ps.l7payload==L7P_TLS_CLIENT_HELLO || ps.ctrack_replay && ps.ctrack_replay->reasm_client_payload==L7P_TLS_CLIENT_HELLO && !ReasmIsEmpty(&ps.ctrack_replay->reasm_client))
		{
			ps.l7payload = L7P_TLS_CLIENT_HELLO;

			bool bReqFull = IsTLSRecordFull(rdata_payload, rlen_payload);
			DLOG(bReqFull ? "TLS client hello is FULL\n" : "TLS client hello is PARTIAL\n");

			if (bReqFull) TLSDebug(rdata_payload, rlen_payload);

			if (ps.ctrack && !l7_payload_match(ps.l7payload, params.reasm_payload_disable))
			{
				// do not reasm retransmissions
				if (!bReqFull && ReasmIsEmpty(&ps.ctrack->reasm_client) && !is_retransmission(&ps.ctrack->pos.client))
				{
					// do not reconstruct unexpected large payload (they are feeding garbage ?)
					// also do not reconstruct if server window size is low
					if (!reasm_client_start(ps.ctrack, IPPROTO_TCP, L7P_TLS_CLIENT_HELLO, TLSRecordLen(dis->data_payload), TCP_MAX_REASM, dis->data_payload, dis->len_payload))
						goto rediscover;
				}

				if (!ReasmIsEmpty(&ps.ctrack->reasm_client))
				{
					if (rawpacket_queue(&ps.ctrack->delayed, &ps.dst, fwmark, desync_fwmark, ifin, ifout, dis->data_pkt, dis->len_pkt, dis->len_payload, &ps.ctrack->pos, false))
					{
						DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ps.ctrack->delayed));
					}
					else
					{
						DLOG_ERR("rawpacket_queue failed !\n");
						goto rediscover;
					}
					if (ReasmIsFull(&ps.ctrack->reasm_client))
					{
						replay_queue(&ps.ctrack->delayed);
						reasm_client_fin(ps.ctrack);
					}
					return VERDICT_DROP;
				}
			}
			ps.bHaveHost = TLSHelloExtractHost(rdata_payload, rlen_payload, ps.host, sizeof(ps.host), true);
		}
		else
		{
			reasm_client_cancel(ps.ctrack);
			if (ps.l7payload==L7P_HTTP_REQ)
				ps.bHaveHost = HttpExtractHost(rdata_payload, rlen_payload, ps.host, sizeof(ps.host));
		}
	}

// UNSOLVED: if reasm is cancelled all packets except the last are passed as is without lua desync
rediscover:
	if (!dp_rediscovery(&ps))
		goto pass_reasm_cancel;

	ps.verdict = desync(ps.dp, fwmark, ifin, ifout, ps.bReverseFixed, ps.ctrack_replay, tpos, ps.l7payload, ps.l7proto, dis, ps.sdip4, ps.sdip6, ps.sdport, mod_pkt, len_mod_pkt, replay_piece, replay_piece_count, reasm_offset, rdata_payload, rlen_payload, NULL, 0);

pass:
	return (!ps.bReverseFixed && (ps.verdict & VERDICT_MASK) == VERDICT_DROP) ? ct_new_postnat_fix(ps.ctrack, dis, mod_pkt, len_mod_pkt) : ps.verdict;
pass_reasm_cancel:
	reasm_client_cancel(ps.ctrack);
	goto pass;
}

// return : true - should continue, false - should stop with verdict
static void quic_reasm_cancel(t_ctrack *ctrack, const char *reason)
{
	reasm_client_cancel(ctrack);
	DLOG("%s\n", reason);
}

static void udp_standard_protocol_probe(const uint8_t *data_payload, size_t len_payload, t_ctrack *ctrack, t_l7proto *l7proto, t_l7payload *l7payload)
{
	t_protocol_probe testers[] = {
		{L7P_QUIC_INITIAL,L7_QUIC,IsQUICInitial,false},
		{L7P_DISCORD_IP_DISCOVERY,L7_DISCORD,IsDiscordIpDiscoveryRequest,false},
		{L7P_STUN,L7_STUN,IsStunMessage,false},
		{L7P_DNS_QUERY,L7_DNS,IsDNSQuery,false},
		{L7P_DNS_RESPONSE,L7_DNS,IsDNSResponse,false},
		{L7P_DHT,L7_DHT,IsDht,false},
		{L7P_DTLS_CLIENT_HELLO,L7_DTLS,IsDTLSClientHello,false},
		{L7P_DTLS_SERVER_HELLO,L7_DTLS,IsDTLSServerHello,false},
		{L7P_UTP_BT_HANDSHAKE,L7_UTP_BT,IsUTP_BTHandshake,false},
		{L7P_WIREGUARD_INITIATION,L7_WIREGUARD,IsWireguardHandshakeInitiation,false},
		{L7P_WIREGUARD_RESPONSE,L7_WIREGUARD,IsWireguardHandshakeResponse,false},
		{L7P_WIREGUARD_COOKIE,L7_WIREGUARD,IsWireguardHandshakeCookie,false},
		{L7P_WIREGUARD_KEEPALIVE,L7_WIREGUARD,IsWireguardKeepalive,false},
		{L7P_WIREGUARD_DATA,L7_WIREGUARD,IsWireguardData,true}};

	protocol_probe(testers, sizeof(testers) / sizeof(*testers), data_payload, len_payload, ctrack, l7proto, l7payload);
}

static const uint8_t *dns_extract_name(const uint8_t *a, const uint8_t *b, const uint8_t *e, char *name, size_t name_size)
{
	size_t nl, off;
	const uint8_t *p;
	bool bptr;
	uint8_t x,y;

	if (!name_size) return NULL;

	bptr = (*a & 0xC0)==0xC0;
	if (bptr)
	{
		if (a+1>=e) return NULL;
		// name pointer
		off = (*a & 0x3F)<<8 | a[1];
		p = b + off;
	}
	else
		// real name
		p = a;

	if (p>=e) return NULL;
	for (nl=0; *p ;)
	{
		if (nl)
		{
			if (nl>=name_size) return NULL;
			name[nl++] = '.';
		}
		// do not support mixed ptr+real
		if ((*p & 0xC0) || (p+*p+1)>=e || (*p+1)>=(name_size-nl)) return NULL;
		for(y=*p++,x=0 ; x<y ; x++,p++) name[nl+x] = tolower(*p);
		nl += y;
	}
	if (nl>=name_size) return NULL;
	name[nl] = 0;
	return bptr ? a+2 : p+1;
}
static bool dns_skip_name(const uint8_t **a, size_t *len)
{
	// 11 higher bits indicate pointer
	// lazy skip name. mixed compressed/uncompressed names are supported
	for(;;)
	{
		if (*len<2) return false;
		if ((**a & 0xC0)==0xC0)
		{
			// pointer is the end
			(*a)+=2; (*len)-=2;
			break;
		}
		if (!**a)
		{
			// zero length is the end
			(*a)++; (*len)--;
			break;
		}
		if (*len<(**a+1)) return false;
		*len-=**a+1;
		*a+=**a+1;
	}
	return true;
}

static bool feed_dns_response(const uint8_t *a, size_t len)
{
	if (!params.cache_hostname) return true;

	// check of minimum header length and response flag
	uint16_t k, typ, off, dlen, qcount = a[4]<<8 | a[5], acount = a[6]<<8 | a[7];
	char s_ip[INET6_ADDRSTRLEN];
	const uint8_t *b = a, *p;
	const uint8_t *e = b + len;
	size_t nl;
	char name[256] = "";

	if (!qcount || len<12 || !(a[2]&0x80)) return false;
	if (!acount)
	{
		DLOG("skipping DNS response without answer\n");
		return false;
	}
	a+=12; len-=12;
	for(k=0,*name = 0 ; k<qcount ; k++)
	{
		if (*name) return false; // we do not support multiple queries with names
		// remember original query name
		if (!(p = dns_extract_name(a, b, e, name, sizeof(name)))) return false;
		len -= p-a;
		if ((len<4) || p[2] || p[3]!=1)	return false;
		typ = pntoh16(p);
		// must be A or AAAA query. others are not interesting
		if (typ!=1 && typ!=28)
		{
			DLOG("skipping DNS query type %u for '%s'\n", typ, name);
			return false;
		}
		else
		{
			DLOG("DNS query type %u for '%s'\n", typ, name);
		}
		// skip type, class
		a=p+4; len-=4;
	}
	if (!*name) return false;
	for(k=0;k<acount;k++)
	{
		if (!dns_skip_name(&a,&len)) return false;
		if (len<10) return false;
		dlen = a[8]<<8 | a[9];
		if (len<(dlen+10)) return false;
		if (a[2]==0 && a[3]==1) // IN class
		{
			typ = pntoh16(a);
			switch(typ)
			{
				case 1: // A
					if (dlen!=4) break;
					if (params.debug && inet_ntop(AF_INET, a+10, s_ip, sizeof(s_ip)))
						DLOG("DNS response type %u : %s\n", typ, s_ip);
					ipcache_put_hostname((struct in_addr *)(a+10), NULL, name, false);
					break;
				case 28: // AAAA
					if (dlen!=16) break;
					if (params.debug && inet_ntop(AF_INET6, a+10, s_ip, sizeof(s_ip)))
						DLOG("DNS response type %u : %s\n", typ, s_ip);
					ipcache_put_hostname(NULL, (struct in6_addr *)(a+10), name, false);
					break;
				default:
					DLOG("skipping DNS response type %u\n", typ);
			}
		}
		len -= 10+dlen; a += 10+dlen;
	}
	return true;
}

static uint8_t dpi_desync_udp_packet_play(
	unsigned int replay_piece, unsigned int replay_piece_count, size_t reasm_offset,
	uint32_t fwmark,
	const char *ifin, const char *ifout,
	const t_ctrack_positions *tpos,
	const struct dissect *dis,
	uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	struct play_state ps;

	if (!play_prolog(&ps, dis, tpos, !!replay_piece_count, ifin, ifout))
		return ps.verdict;

	uint32_t desync_fwmark = fwmark | params.desync_fwmark;
	uint8_t defrag[UDP_MAX_REASM];
	uint8_t *data_decrypt = NULL;
	size_t len_decrypt = 0;

	if (dis->len_payload)
	{
		udp_standard_protocol_probe(dis->data_payload, dis->len_payload, ps.ctrack, &ps.l7proto, &ps.l7payload);

		if (!ps.bReverse)
		{
			if (ps.l7payload==L7P_QUIC_INITIAL)
			{
				uint8_t clean[UDP_MAX_REASM], *pclean;
				size_t clean_len;

				if (replay_piece_count)
				{
					clean_len = ps.ctrack_replay->reasm_client.size_present;
					pclean = ps.ctrack_replay->reasm_client.packet;
				}
				else
				{
					clean_len = sizeof(clean);
					pclean = QUICDecryptInitial(dis->data_payload, dis->len_payload, clean, &clean_len) ? clean : NULL;
				}
				if (pclean)
				{
					bool reasm_disable = l7_payload_match(ps.l7payload, params.reasm_payload_disable);
					if (ps.ctrack && !reasm_disable && !ReasmIsEmpty(&ps.ctrack->reasm_client))
					{
						if (ReasmHasSpace(&ps.ctrack->reasm_client, clean_len))
						{
							reasm_client_feed(ps.ctrack, IPPROTO_UDP, clean, clean_len);
							pclean = ps.ctrack->reasm_client.packet;
							clean_len = ps.ctrack->reasm_client.size_present;
						}
						else
						{
							DLOG("QUIC reasm is too long. cancelling.\n");
							goto rediscover_cancel;
						}
					}
					size_t hello_offset, hello_len, defrag_len = sizeof(defrag);
					bool bFull;
					if (QUICDefragCrypto(pclean, clean_len, defrag, &defrag_len, &bFull))
					{
						if (bFull)
						{
							DLOG("QUIC initial contains CRYPTO with full fragment coverage\n");

							bool bIsHello = IsQUICCryptoHello(defrag, defrag_len, &hello_offset, &hello_len);
							bool bReqFull = bIsHello ? IsTLSHandshakeFull(defrag + hello_offset, hello_len) : false;

							DLOG(bIsHello ? bReqFull ? "packet contains full TLS ClientHello\n" : "packet contains partial TLS ClientHello\n" : "packet does not contain TLS ClientHello\n");

							if (bReqFull) TLSDebugHandshake(defrag + hello_offset, hello_len);

							if (ps.ctrack && !reasm_disable)
							{
								if (bIsHello && !bReqFull && ReasmIsEmpty(&ps.ctrack->reasm_client))
								{
									// preallocate max buffer to avoid reallocs that cause memory copy
									if (!reasm_client_start(ps.ctrack, IPPROTO_UDP, L7P_QUIC_INITIAL, UDP_MAX_REASM, UDP_MAX_REASM, clean, clean_len))
										goto rediscover_cancel;
								}
								if (!ReasmIsEmpty(&ps.ctrack->reasm_client))
								{
									if (rawpacket_queue(&ps.ctrack->delayed, &ps.dst, fwmark, desync_fwmark, ifin, ifout, dis->data_pkt, dis->len_pkt, dis->len_payload, &ps.ctrack->pos, false))
									{
										DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ps.ctrack->delayed));
									}
									else
									{
										DLOG_ERR("rawpacket_queue failed !\n");
										goto rediscover_cancel;
									}
									if (bReqFull)
									{
										replay_queue(&ps.ctrack->delayed);
										reasm_client_fin(ps.ctrack);
									}
									return ct_new_postnat_fix(ps.ctrack, dis, mod_pkt, len_mod_pkt);
								}
							}

							if (bIsHello)
							{
								data_decrypt = defrag + hello_offset;
								len_decrypt = hello_len;
								ps.bHaveHost = TLSHelloExtractHostFromHandshake(data_decrypt, len_decrypt, ps.host, sizeof(ps.host), true);
							}
							else
							{
								quic_reasm_cancel(ps.ctrack, "QUIC initial without ClientHello");
							}
						}
						else
						{
							DLOG("QUIC initial contains CRYPTO with partial fragment coverage\n");
							if (ps.ctrack && !reasm_disable)
							{
								if (ReasmIsEmpty(&ps.ctrack->reasm_client))
								{
									// preallocate max buffer to avoid reallocs that cause memory copy
									if (!reasm_client_start(ps.ctrack, IPPROTO_UDP, L7P_QUIC_INITIAL, UDP_MAX_REASM, UDP_MAX_REASM, clean, clean_len))
										goto rediscover_cancel;
								}
								if (rawpacket_queue(&ps.ctrack->delayed, &ps.dst, fwmark, desync_fwmark, ifin, ifout, dis->data_pkt, dis->len_pkt, dis->len_payload, &ps.ctrack->pos, false))
								{
									DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ps.ctrack->delayed));
								}
								else
								{
									DLOG_ERR("rawpacket_queue failed !\n");
									goto rediscover_cancel;
								}
								return ct_new_postnat_fix(ps.ctrack, dis, mod_pkt, len_mod_pkt);
							}
							quic_reasm_cancel(ps.ctrack, "QUIC initial fragmented CRYPTO");
						}
					}
					else
					{
						// defrag failed
						quic_reasm_cancel(ps.ctrack, "QUIC initial defrag CRYPTO failed");
					}
				}
				else
				{
					// decrypt failed
					quic_reasm_cancel(ps.ctrack, "QUIC initial decryption failed");
				}
			}
		}

		if (ps.l7payload==L7P_DNS_RESPONSE)
			feed_dns_response(dis->data_payload, dis->len_payload);
	} // len_payload

// UNSOLVED: if reasm is cancelled all packets except the last are passed as is without lua desync
rediscover_cancel:
	reasm_client_cancel(ps.ctrack);

	if (!dp_rediscovery(&ps))
		goto pass;

	ps.verdict = desync(ps.dp, fwmark, ifin, ifout, ps.bReverseFixed, ps.ctrack_replay, tpos, ps.l7payload, ps.l7proto, dis, ps.sdip4, ps.sdip6, ps.sdport, mod_pkt, len_mod_pkt, replay_piece, replay_piece_count, reasm_offset, NULL, 0, data_decrypt, len_decrypt);
pass:
	return (!ps.bReverseFixed && (ps.verdict & VERDICT_MASK) == VERDICT_DROP) ? ct_new_postnat_fix(ps.ctrack, dis, mod_pkt, len_mod_pkt) : ps.verdict;
}

// conntrack is supported only for RELATED icmp
// ip matched in both directions if conntrack is unavailable
static uint8_t dpi_desync_icmp_packet(
	uint32_t fwmark,
	const char *ifin, const char *ifout,
	const struct dissect *dis,
	uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	uint8_t verdict = VERDICT_PASS;

	// additional safety check
	if (!!dis->ip == !!dis->ip6) return verdict;

	const uint8_t *pkt_attached;
	size_t len_attached;
	const char *ifname;
	struct sockaddr_storage src, dst;
	const char *ssid = NULL;
	struct desync_profile *dp = NULL;
	t_l7payload l7payload = L7P_ICMP;
	t_ctrack *ctrack = NULL;
	bool bReverse, bReverseFixed;

	extract_endpoints(dis->ip, dis->ip6, NULL, NULL, &src, &dst);

	switch(dis->icmp->icmp_type)
	{
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
		case ICMP_REDIRECT:
		case ICMP6_DST_UNREACH:
		//case ICMP6_TIME_EXCEEDED: // same as ICMP_TIME_EXCEEDED = 3
		case ICMP6_PACKET_TOO_BIG:
		case ICMP6_PARAM_PROB:
			pkt_attached = dis->data_payload;
			break;
		default:
			pkt_attached = NULL;
	}
	if (pkt_attached)
	{
		struct dissect adis;
		len_attached = pkt_attached - dis->data_payload + dis->len_payload;
		proto_dissect_l3l4(pkt_attached, len_attached, &adis, true); // dissect without payload length checks - can be partial
		if (!adis.ip && !adis.ip6)
			DLOG("attached packet is invalid\n");
		else
		{
			l7payload = adis.ip ? L7P_IPV4 : L7P_IPV6;
			DLOG("attached packet\n");
			packet_debug(false, &adis);
			if (ConntrackPoolDoubleSearch(&params.conntrack, &adis, &ctrack, &bReverse))
			{
				// invert direction. they are answering to this packet
				bReverse = !bReverse;
				DLOG("found conntrack entry. inverted reverse=%u\n",bReverse);
				if (ctrack->dp_search_complete && ctrack->dp)
				{
					// RELATED icmp processed within base connection profile
					dp = ctrack->dp;
					DLOG("using desync profile %u (%s) from conntrack entry\n", dp->n, PROFILE_NAME(dp));
				}
			}
			else
				DLOG("conntrack entry not found\n");
		}
	}

	bReverseFixed = ctrack ? (bReverse ^ params.server) : (bReverse = ifin && *ifin && (!ifout || !*ifout));

#ifdef HAS_FILTER_SSID
	ifname = bReverse ? ifin : ifout;
	if ((ssid = wlan_ssid_search_ifname(ifname)))
		DLOG("found ssid for %s : %s\n", ifname, ssid);
	else if (!ctrack)
	{
		// we dont know direction for sure
		// search opposite interface
		ifname = bReverse ? ifout : ifin;
		if ((ssid = wlan_ssid_search_ifname(ifname)))
			DLOG("found ssid for %s : %s\n", ifname, ssid);
	}
#endif
	if (!dp)
	{
		bool hostname_is_ip = false;
		char host[256];
		const char *hostname = NULL;
		if (ctrack && ctrack->hostname)
		{
			hostname = ctrack->hostname;
			hostname_is_ip = ctrack->hostname_is_ip;
		}
		else if (ipcache_get_hostname(dis->ip ? &dis->ip->ip_dst : NULL, dis->ip6 ? &dis->ip6->ip6_dst : NULL, host, sizeof(host), &hostname_is_ip) ||
			ipcache_get_hostname(dis->ip ? &dis->ip->ip_src : NULL, dis->ip6 ? &dis->ip6->ip6_src : NULL, host, sizeof(host), &hostname_is_ip))
		{
			hostname = host;
		}

		dp = dp_find(
			&params.desync_profiles,
			dis->proto,
			dis->ip ? &dis->ip->ip_dst : NULL, dis->ip6 ? &dis->ip6->ip6_dst : NULL,
			dis->ip ? &dis->ip->ip_src : NULL, dis->ip6 ? &dis->ip6->ip6_src : NULL,
			0, dis->icmp->icmp_type, dis->icmp->icmp_code,
			hostname, hostname_is_ip,
			L7_UNKNOWN, ssid, NULL, NULL, NULL);
		if (!dp)
		{
			DLOG("matching desync profile not found\n");
			return verdict;
		}
	}

	const struct in_addr *sdip4;
	const struct in6_addr *sdip6;
	sdip6 = dis->ip6 ? bReverseFixed ? &dis->ip6->ip6_src : &dis->ip6->ip6_dst : NULL;
	sdip4 = dis->ip ? bReverseFixed ? &dis->ip->ip_src : &dis->ip->ip_dst : NULL;

	verdict = desync(
		dp, fwmark, ifin, ifout, bReverseFixed, ctrack, NULL, l7payload, ctrack ? ctrack->l7proto : L7_UNKNOWN,
		dis, sdip4, sdip6, 0, mod_pkt, len_mod_pkt, 0, 0, 0, NULL, 0, NULL, 0);

	return verdict;
}

// undissected l4+
// conntrack is unsupported
// ip matched in both directions
static uint8_t dpi_desync_ip_packet(
	uint32_t fwmark,
	const char *ifin, const char *ifout,
	const struct dissect *dis,
	uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	uint8_t verdict = VERDICT_PASS;

	// additional safety check
	if (!!dis->ip == !!dis->ip6) return verdict;

	struct sockaddr_storage src, dst;
	const char *ssid = NULL;
	struct desync_profile *dp;

	extract_endpoints(dis->ip, dis->ip6, NULL, NULL, &src, &dst);
#ifdef HAS_FILTER_SSID
	if ((ssid = wlan_ssid_search_ifname(ifin)))
		DLOG("found ssid for %s : %s\n", ifin, ssid);
	else
	{
		// we dont know direction for sure
		// search opposite interface
		if ((ssid = wlan_ssid_search_ifname(ifout)))
			DLOG("found ssid for %s : %s\n", ifout, ssid);
	}
#endif

	bool hostname_is_ip = false;
	const char *hostname = NULL;
	char host[256];
	if (ipcache_get_hostname(dis->ip ? &dis->ip->ip_dst : NULL, dis->ip6 ? &dis->ip6->ip6_dst : NULL, host, sizeof(host), &hostname_is_ip) ||
		ipcache_get_hostname(dis->ip ? &dis->ip->ip_src : NULL, dis->ip6 ? &dis->ip6->ip6_src : NULL, host, sizeof(host), &hostname_is_ip))
	{
		hostname = host;
	}
	dp = dp_find(
		&params.desync_profiles,
		dis->proto,
		dis->ip ? &dis->ip->ip_dst : NULL, dis->ip6 ? &dis->ip6->ip6_dst : NULL,
		dis->ip ? &dis->ip->ip_src : NULL, dis->ip6 ? &dis->ip6->ip6_src : NULL,
		0, 0xFF, 0xFF,
		hostname, hostname_is_ip,
		L7_UNKNOWN, ssid, NULL, NULL, NULL);
	if (!dp)
	{
		DLOG("matching desync profile not found\n");
		return verdict;
	}

	bool bReverse = ifin && *ifin && (!ifout || !*ifout);

	const struct in_addr *sdip4;
	const struct in6_addr *sdip6;
	sdip6 = dis->ip6 ? bReverse ? &dis->ip6->ip6_src : &dis->ip6->ip6_dst : NULL;
	sdip4 = dis->ip ? bReverse ? &dis->ip->ip_src : &dis->ip->ip_dst : NULL;

	verdict = desync(
		dp, fwmark, ifin, ifout, bReverse, NULL, NULL, L7P_UNKNOWN, L7_UNKNOWN,
		dis, sdip4, sdip6, 0, mod_pkt, len_mod_pkt, 0, 0, 0, NULL, 0, NULL, 0);

	return verdict;
}


static uint8_t dpi_desync_packet_play(
	unsigned int replay_piece, unsigned int replay_piece_count, size_t reasm_offset, uint32_t fwmark, const char *ifin, const char *ifout,
	const t_ctrack_positions *tpos,
	const uint8_t *data_pkt, size_t len_pkt,
	uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	struct dissect dis;
	uint8_t verdict = VERDICT_PASS;

	// NOTE ! OS can pass wrong checksum to queue. cannot rely on it !

	proto_dissect_l3l4(data_pkt, len_pkt, &dis, false);
	if (!!dis.ip != !!dis.ip6)
	{
		packet_debug(!!replay_piece_count, &dis);

		// fix csum if unmodified and if OS can pass wrong csum to queue (depends on OS)
		// modified means we have already fixed the checksum or made it invalid intentionally
		// this is the only point we VIOLATE const to fix the checksum in the original buffer to avoid copying to mod_pkt
		if (dis.tcp)
		{
			verdict = dpi_desync_tcp_packet_play(replay_piece, replay_piece_count, reasm_offset, fwmark, ifin, ifout, tpos, &dis, mod_pkt, len_mod_pkt);
			verdict_tcp_csum_fix(verdict, (struct tcphdr *)dis.tcp, dis.transport_len, dis.ip, dis.ip6);
		}
		else if (dis.udp)
		{
			verdict = dpi_desync_udp_packet_play(replay_piece, replay_piece_count, reasm_offset, fwmark, ifin, ifout, tpos, &dis, mod_pkt, len_mod_pkt);
			verdict_udp_csum_fix(verdict, (struct udphdr *)dis.udp, dis.transport_len, dis.ip, dis.ip6);
		}
		else if (dis.icmp)
		{
			verdict = dpi_desync_icmp_packet(fwmark, ifin, ifout, &dis, mod_pkt, len_mod_pkt);
			verdict_icmp_csum_fix(verdict, (struct icmp46 *)dis.icmp, dis.transport_len, dis.ip6);
		}
		else
			verdict = dpi_desync_ip_packet(fwmark, ifin, ifout, &dis, mod_pkt, len_mod_pkt);
	}
	else
		DLOG("invalid packet - neither ipv4 or ipv6\n");
	return verdict;
}
uint8_t dpi_desync_packet(uint32_t fwmark, const char *ifin, const char *ifout, const uint8_t *data_pkt, size_t len_pkt, uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	// NOTE ! OS can pass wrong checksum to queue. cannot rely on it !

	ipcachePurgeRateLimited(&params.ipcache, params.ipcache_lifetime);
	return dpi_desync_packet_play(0, 0, 0, fwmark, ifin, ifout, NULL, data_pkt, len_pkt, mod_pkt, len_mod_pkt);
}



static bool replay_queue(struct rawpacket_tailhead *q)
{
	struct rawpacket *rp;
	size_t offset;
	unsigned int i, count;
	uint8_t mod[RECONSTRUCT_MAX_SIZE];
	size_t modlen;
	uint32_t seq0;
	t_ctrack_position *pos;
	bool b = true, bseq;

	for (i = 0, offset = 0, count = rawpacket_queue_count(q); (rp = rawpacket_dequeue(q)); rawpacket_free(rp), i++)
	{
		// TCP: track reasm_offset using sequence numbers
		if ((bseq = rp->tpos_present && rp->tpos.ipproto==IPPROTO_TCP))
		{
			pos = rp->server_side ? &rp->tpos.server : &rp->tpos.client;
			if (i)
				offset = pos->seq_last - seq0;
			else
				seq0 = pos->seq_last;
		}

		DLOG("REPLAYING delayed packet #%u offset %zu\n", i+1, offset);
		modlen = sizeof(mod);
		uint8_t verdict = dpi_desync_packet_play(i, count, offset, rp->fwmark_orig, rp->ifin, rp->ifout, rp->tpos_present ? &rp->tpos : NULL, rp->packet, rp->len, mod, &modlen);
		switch (verdict & VERDICT_MASK)
		{
		case VERDICT_MODIFY:
			DLOG("SENDING delayed packet #%u modified\n", i+1);
			b &= rawsend((struct sockaddr*)&rp->dst,rp->fwmark,rp->ifout,mod,modlen);
			break;
		case VERDICT_PASS:
			DLOG("SENDING delayed packet #%u unmodified\n", i+1);
			b &= rawsend_rp(rp);
			break;
		case VERDICT_DROP:
			DLOG("DROPPING delayed packet #%u\n", i+1);
			break;
		}

		if (!bseq)
			offset += rp->len_payload;
	}
	return b;
}
