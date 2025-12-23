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
		if ((!probe[i].l7match || *l7proto==probe[i].l7) && probe[i].check(data_payload, len_payload))
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


static bool dp_match(
	struct desync_profile *dp,
	uint8_t l3proto,
	const struct in_addr *ip, const struct in6_addr *ip6, uint16_t port,
	const char *hostname, bool bNoSubdom, t_l7proto l7proto, const char *ssid,
	bool *bCheckDone, bool *bCheckResult, bool *bExcluded)
{
	bool bHostlistsEmpty;

	if (bCheckDone) *bCheckDone = false;

	if (!HostlistsReloadCheckForProfile(dp)) return false;

	if ((ip && !dp->filter_ipv4) || (ip6 && !dp->filter_ipv6))
		// L3 filter does not match
		return false;

	if ((l3proto == IPPROTO_TCP && !port_filters_in_range(&dp->pf_tcp, port)) || (l3proto == IPPROTO_UDP && !port_filters_in_range(&dp->pf_udp, port)))
		// L4 filter does not match
		return false;

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
	if (!IpsetCheck(dp, ip, ip6))
		// target ip does not match
		return false;

	// autohostlist profile matching l3/l4/l7 filter always win if we have a hostname. no matter it matches or not.
	if (dp->hostlist_auto && hostname) return true;

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
	const struct in_addr *ip, const struct in6_addr *ip6, uint16_t port,
	const char *hostname, bool bNoSubdom, t_l7proto l7proto, const char *ssid,
	bool *bCheckDone, bool *bCheckResult, bool *bExcluded)
{
	struct desync_profile_list *dpl;
	if (params.debug)
	{
		char s[40];
		ntopa46(ip, ip6, s, sizeof(s));
		DLOG("desync profile search for %s ip=%s port=%u l7proto=%s ssid='%s' hostname='%s'\n", proto_name(l3proto), s, port, l7proto_str(l7proto), ssid ? ssid : "", hostname ? hostname : "");
	}
	if (bCheckDone) *bCheckDone = false;
	LIST_FOREACH(dpl, head, next)
	{
		if (dp_match(&dpl->dp, l3proto, ip, ip6, port, hostname, bNoSubdom, l7proto, ssid, bCheckDone, bCheckResult, bExcluded))
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
				struct ip *ip;
				struct ip6_hdr *ip6;
				struct tcphdr *tcp;
				uint16_t pktlen;

				if (dis->ip)
				{
					ip = (struct ip*)pkt; ip6=NULL;
					pktlen = sizeof(struct iphdr) + sizeof(struct tcphdr);
					*ip = *dis->ip;
					ip->ip_hl = sizeof(struct iphdr)/4; // remove ip options
					ip->ip_len = htons(pktlen);
					ip->ip_id=0;
					tcp = (struct tcphdr*)(ip+1);
					*tcp = *dis->tcp;
				}
				else if (dis->ip6)
				{
					ip6 = (struct ip6_hdr*)pkt; ip=NULL;
					pktlen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
					*ip6 = *dis->ip6;
					ip6->ip6_plen = htons(sizeof(struct tcphdr));
					ip6->ip6_nxt = IPPROTO_TCP;
					ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(ctrack->pos.server.ip6flow);
					tcp = (struct tcphdr*)(ip6+1);
					*tcp = *dis->tcp;
				}
				reverse_ip(ip,ip6); // also fixes ip4 checksum
				reverse_tcp(tcp);
				tcp->th_off = sizeof(struct tcphdr)/4; // remove tcp options
				tcp->th_flags = TH_RST;
				tcp->th_win = ctrack->pos.server.winsize;
				tcp_fix_checksum(tcp, sizeof(struct tcphdr), ip, ip6);

				DLOG("sending RST to retransmitter\n");
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
			fill_client_ip_port(client, client_ip_port, sizeof(client_ip_port));
			auto_hostlist_reset_fail_counter(ctrack->dp, ctrack->hostname, client_ip_port, ctrack->l7proto);
		}
		else if (tpos->client.pcounter >= ctrack->dp->hostlist_auto_udp_out)
		{
			// failure
			ctrack->failure_detect_finalized = true;
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

static bool rawpacket_queue_csum_fix(struct rawpacket_tailhead *q, const struct dissect *dis, const t_ctrack_positions *tpos, const struct sockaddr_storage* dst, uint32_t fwmark, uint32_t desync_fwmark, const char *ifin, const char *ifout)
{
	// this breaks const pointer to l4 header
	if (dis->tcp)
		verdict_tcp_csum_fix(VERDICT_PASS, (struct tcphdr *)dis->tcp, dis->transport_len, dis->ip, dis->ip6);
	else if (dis->udp)
		verdict_udp_csum_fix(VERDICT_PASS, (struct udphdr *)dis->udp, dis->transport_len, dis->ip, dis->ip6);
	return rawpacket_queue(q, dst, fwmark, desync_fwmark, ifin, ifout, dis->data_pkt, dis->len_pkt, dis->len_payload, tpos);
}


static bool reasm_start(t_ctrack *ctrack, t_reassemble *reasm, uint8_t proto, uint32_t seq, size_t sz, size_t szMax, const uint8_t *data_payload, size_t len_payload)
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
static bool reasm_client_start(t_ctrack *ctrack, uint8_t proto, size_t sz, size_t szMax, const uint8_t *data_payload, size_t len_payload)
{
	if (!ctrack) return false;
	// if winsize_calc==0 it means we dont know server window size - no incoming packets redirected ?
	if (proto==IPPROTO_TCP && ctrack->pos.server.winsize_calc && (ctrack->pos.server.winsize_calc < sz))
	{
		// this is rare but possible situation
		// server gave us too small tcp window
		// client will not send all pieces of reasm
		// if we drop packets and wait for next pieces we will see nothing but retransmissions
		DLOG("reasm cancelled because server window size %u is smaller than expected reasm size %u\n", ctrack->pos.server.winsize_calc, sz);
		return false;
	}
	return reasm_start(ctrack, &ctrack->reasm_client, proto, (proto == IPPROTO_TCP) ? ctrack->pos.client.seq_last : 0, sz, szMax, data_payload, len_payload);
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
	if (ctrack && (params.server ? ctrack->pos.server.pcounter : ctrack->pos.client.pcounter) == 1 || dis->tcp && (tcp_syn_segment(dis->tcp) || tcp_synack_segment(dis->tcp)))
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
		}
		return VERDICT_MODIFY | VERDICT_NOCSUM;
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
			return (ps < range->to.pos) || !range->upper_cutoff && (ps == range->to.pos);
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
		return true;
	}
	ip_cache_item *ipc = ipcacheTouch(&params.ipcache, a4, a6, NULL);
	if (!ipc)
	{
		DLOG_ERR("ipcache_get_hostname: out of memory\n");
		return false;
	}
	if (ipc->hostname)
	{
		DLOG("got cached hostname (is_ip=%u): %s\n", ipc->hostname_is_ip, ipc->hostname);
		snprintf(hostname, hostname_buf_len, "%s", ipc->hostname);
		if (hostname_is_ip) *hostname_is_ip = ipc->hostname_is_ip;
	}
	else
		*hostname = 0;
	return true;
}
static void ipcache_update_ttl(t_ctrack *ctrack, const struct in_addr *a4, const struct in6_addr *a6, const char *iface)
{
	// no need to cache ttl in server mode because first packet is incoming
	if (ctrack && !params.server)
	{
		ip_cache_item *ipc = ipcacheTouch(&params.ipcache, a4, a6, iface);
		if (!ipc)
		{
			DLOG_ERR("ipcache: out of memory\n");
			return;
		}
		if (ctrack->incoming_ttl)
		{
			if (ipc->ttl != ctrack->incoming_ttl)
			{
				DLOG("updated ttl cache\n");
				ipc->ttl = ctrack->incoming_ttl;
			}
		}
		else if (ipc->ttl)
		{
			DLOG("got cached ttl %u\n", ipc->ttl);
			ctrack->incoming_ttl = ipc->ttl;
		}
	}
}
static void ipcache_get_ttl(t_ctrack *ctrack, const struct in_addr *a4, const struct in6_addr *a6, const char *iface)
{
	// no need to cache ttl in server mode because first packet is incoming
	if (ctrack && !ctrack->incoming_ttl && !params.server)
	{
		ip_cache_item *ipc = ipcacheTouch(&params.ipcache, a4, a6, iface);
		if (!ipc)
			DLOG_ERR("ipcache: out of memory\n");
		else if (ipc->ttl)
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
		if (lv & ~VERDICT_MASK)
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
	t_lua_desync_context ctx = { .magic = 0, .dp = dp, .ctrack = ctrack, .dis = dis, .cancel = false, .incoming = bIncoming };
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
		b_cutoff_all = b_unwanted_payload = true;
		ctx.func_n = 1;
		LIST_FOREACH(func, &dp->lua_desync, next)
		{
			ctx.func = func->func;
			desync_instance(func->func, dp->n, ctx.func_n, instance, sizeof(instance));
			ctx.instance = instance;
			range = bIncoming ? &func->range_in : &func->range_out;

			if (b_unwanted_payload)
				b_unwanted_payload &= !l7_payload_match(l7payload, func->payload_type);

			if (b_cutoff_all)
			{
				if (lua_instance_cutoff_check(&ctx, bIncoming))
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
			ctx.func_n++;
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
			lua_pushf_dissect(dis);
			lua_pushf_ctrack(ctrack, tpos, bIncoming);
			lua_pushf_int("profile_n", dp->n);
			if (dp->name) lua_pushf_str("profile_name", dp->name);
			if (dp->n_tpl) lua_pushf_int("template_n", dp->n_tpl);
			if (dp->name_tpl) lua_pushf_str("template_name", dp->name_tpl);
			if (dp->cookie) lua_pushf_str("cookie", dp->cookie);
			lua_pushf_bool("outgoing", !bIncoming);
			lua_pushf_str("ifin", (ifin && *ifin) ? ifin : NULL);
			lua_pushf_str("ifout", (ifout && *ifout) ? ifout : NULL);
			lua_pushf_lint("fwmark", fwmark);
			lua_pushf_table("target");
			lua_getfield(params.L,-1,"target");
			if (sdport) lua_pushf_int("port",sdport);
			if (sdp4) lua_pushf_lstr("ip",(const char*)sdp4,sizeof(*sdp4));
			if (sdp6) lua_pushf_lstr("ip6",(const char*)sdp6,sizeof(*sdp6));
			lua_pop(params.L,1);
			lua_pushf_bool("replay", !!replay_piece_count);
			if (replay_piece_count)
			{
				lua_pushf_int("replay_piece", replay_piece+1);
				lua_pushf_int("replay_piece_count", replay_piece_count);
				lua_pushf_bool("replay_piece_last", (replay_piece+1)>=replay_piece_count);
			}
			lua_pushf_str("l7payload", l7payload_str(l7payload));
			lua_pushf_str("l7proto", l7proto_str(l7proto));
			lua_pushf_int("reasm_offset", reasm_offset);
			lua_pushf_raw("reasm_data", rdata_payload, rlen_payload);
			lua_pushf_raw("decrypt_data", data_decrypt, len_decrypt);
			//if (ctrack) lua_pushf_reg("instance_cutoff", ctrack->lua_instance_cutoff);
			if (dis->tcp)
			{
				// recommended mss value for generated packets
				if (rpos && rpos->mss)
					lua_pushf_int("tcp_mss", rpos->mss);
				else
					lua_pushf_global("tcp_mss", "DEFAULT_MSS");
			}
			ref_arg = luaL_ref(params.L, LUA_REGISTRYINDEX);

			ctx.func_n = 1;
			LIST_FOREACH(func, &dp->lua_desync, next)
			{
				ctx.func = func->func;
				desync_instance(func->func, dp->n, ctx.func_n, instance, sizeof(instance));
				ctx.instance = instance;

				if (!lua_instance_cutoff_check(&ctx, bIncoming))
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
							lua_pushlightuserdata(params.L, &ctx);
							lua_rawgeti(params.L, LUA_REGISTRYINDEX, ref_arg);
							lua_pushf_args(&func->args, -1, true);
							lua_pushf_str("func", func->func);
							lua_pushf_int("func_n", ctx.func_n);
							lua_pushf_str("func_instance", instance);

							// lua should not store and access ctx outside of this call
							// if this happens make our best to prevent access to bad memory
							// this is not crash-proof but better than nothing
							ctx.magic = MAGIC_CTX; // mark struct as valid
							status = lua_pcall(params.L, 2, LUA_MULTRET, 0);
							ctx.magic = 0; // mark struct as invalid

							if (status)
							{
								lua_dlog_error();
								goto err;
							}
							if (!desync_get_result(&verdict_func))
								goto err;
							switch (verdict_func & VERDICT_MASK)
							{
							case VERDICT_MODIFY:
								if (verdict == VERDICT_PASS) verdict = VERDICT_MODIFY;
								break;
							case VERDICT_DROP:
								verdict = VERDICT_DROP;
							}
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
				if (ctx.cancel) break;
				ctx.func_n++;
			}
		}

		if (verdict == VERDICT_MODIFY)
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
				b = lua_reconstruct_dissect(-1, mod_pkt, len_mod_pkt, false, false);
				lua_pop(params.L, 2);
				if (!b)
				{
					DLOG_ERR("failed to reconstruct packet after VERDICT_MODIFY\n");
					// to reduce memory copying we used original packet buffer for reconstruction.
					// it may have been modified. windows and BSD will send modified data despite of VERDICT_PASS.
					// force same behavior on all OS
					// it's LUA script error, they passed bad data
					verdict = VERDICT_DROP;
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
		char ip[40];
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

static uint8_t dpi_desync_tcp_packet_play(
	unsigned int replay_piece, unsigned int replay_piece_count, size_t reasm_offset,
	uint32_t fwmark,
	const char *ifin, const char *ifout,
	const t_ctrack_positions *tpos,
	const struct dissect *dis,
	uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	uint8_t verdict = VERDICT_PASS;

	// additional safety check
	if (!!dis->ip == !!dis->ip6) return verdict;

	struct desync_profile *dp = NULL;
	t_ctrack *ctrack = NULL, *ctrack_replay = NULL;
	bool bReverse = false, bReverseFixed = false;
	struct sockaddr_storage src, dst;
	const struct in_addr *sdip4;
	const struct in6_addr *sdip6;
	uint16_t sdport;
	char host[256];
	const char *ifname = NULL, *ssid = NULL;
	t_l7proto l7proto = L7_UNKNOWN;
	t_l7payload l7payload = dis->len_payload ? L7P_UNKNOWN : L7P_EMPTY;

	uint32_t desync_fwmark = fwmark | params.desync_fwmark;

	if (replay_piece_count)
	{
		// in replay mode conntrack_replay is not NULL and ctrack is NULL

		//ConntrackPoolDump(&params.conntrack);
		if (!ConntrackPoolDoubleSearch(&params.conntrack, dis, &ctrack_replay, &bReverse) || bReverse)
			return verdict;
		bReverseFixed = bReverse ^ params.server;
		setup_direction(dis, bReverseFixed, &src, &dst, &sdip4, &sdip6, &sdport);

		ifname = bReverse ? ifin : ifout;
#ifdef HAS_FILTER_SSID
		ssid = wlan_ssid_search_ifname(ifname);
		if (ssid) DLOG("found ssid for %s : %s\n", ifname, ssid);
#endif
		l7proto = ctrack_replay->l7proto;
		dp = ctrack_replay->dp;
		if (dp)
			DLOG("using cached desync profile %u (%s)\n", dp->n, PROFILE_NAME(dp));
		else if (!ctrack_replay->dp_search_complete)
		{
			dp = ctrack_replay->dp = dp_find(&params.desync_profiles, IPPROTO_TCP, sdip4, sdip6, sdport, ctrack_replay->hostname, ctrack_replay->hostname_is_ip, l7proto, ssid, NULL, NULL, NULL);
			ctrack_replay->dp_search_complete = true;
		}
		if (!dp)
		{
			DLOG("matching desync profile not found\n");
			return verdict;
		}
	}
	else
	{
		// in real mode ctrack may be NULL or not NULL, conntrack_replay is equal to ctrack

		if (!params.ctrack_disable)
		{
			ConntrackPoolPurge(&params.conntrack);
			if (ConntrackPoolFeed(&params.conntrack, dis, &ctrack, &bReverse))
			{
				dp = ctrack->dp;
				ctrack_replay = ctrack;
			}
		}
		// in absence of conntrack guess direction by presence of interface names. won't work on BSD
		bReverseFixed = ctrack ? (bReverse ^ params.server) : (bReverse = ifin && ifin && (!ifout || !*ifout));
		setup_direction(dis, bReverseFixed, &src, &dst, &sdip4, &sdip6, &sdport);
		ifname = bReverse ? ifin : ifout;
#ifdef HAS_FILTER_SSID
		ssid = wlan_ssid_search_ifname(ifname);
		if (ssid) DLOG("found ssid for %s : %s\n", ifname, ssid);
#endif
		if (ctrack) l7proto = ctrack->l7proto;
		if (dp)
			DLOG("using cached desync profile %u (%s)\n", dp->n, PROFILE_NAME(dp));
		else if (!ctrack || !ctrack->dp_search_complete)
		{
			const char *hostname = NULL;
			bool hostname_is_ip = false;
			if (ctrack)
			{
				hostname = ctrack->hostname;
				hostname_is_ip = ctrack->hostname_is_ip;
				if (!hostname && !bReverse)
				{
					if (ipcache_get_hostname(sdip4, sdip6, host, sizeof(host), &hostname_is_ip) && *host)
						if (!(hostname = ctrack->hostname = strdup(host)))
							DLOG_ERR("strdup(host): out of memory\n");
				}
			}
			dp = dp_find(&params.desync_profiles, IPPROTO_TCP, sdip4, sdip6, sdport, hostname, hostname_is_ip, l7proto, ssid, NULL, NULL, NULL);
			if (ctrack)
			{
				ctrack->dp = dp;
				ctrack->dp_search_complete = true;
			}
		}
		if (!dp)
		{
			DLOG("matching desync profile not found\n");
			return verdict;
		}

		HostFailPoolPurgeRateLimited(&dp->hostlist_auto_fail_counters);

		//ConntrackPoolDump(&params.conntrack);

		if (bReverseFixed)
		{
			if (ctrack && !ctrack->incoming_ttl)
			{
				ctrack->incoming_ttl = ttl46(dis->ip, dis->ip6);
				DLOG("incoming TTL %u\n", ctrack->incoming_ttl);
			}
			ipcache_update_ttl(ctrack, sdip4, sdip6, ifin);
		}
		else
			ipcache_get_ttl(ctrack, sdip4, sdip6, ifout);

	} // !replay

	const uint8_t *rdata_payload = dis->data_payload;
	size_t rlen_payload = dis->len_payload;

	bool bCheckDone, bCheckResult, bCheckExcluded;
	if (ctrack_replay)
	{
		bCheckDone = ctrack_replay->bCheckDone;
		bCheckResult = ctrack_replay->bCheckResult;
		bCheckExcluded = ctrack_replay->bCheckExcluded;
	}
	else
		bCheckDone = bCheckResult = bCheckExcluded = false;

	bool bHaveHost = false, bHostIsIp = false;
	if (bReverse)
	{
		// protocol detection
		if (!(dis->tcp->th_flags & TH_SYN) && dis->len_payload)
		{
			t_protocol_probe testers[] = {
				{L7P_TLS_SERVER_HELLO,L7_TLS,IsTLSServerHelloPartial,false},
				{L7P_HTTP_REPLY,L7_HTTP,IsHttpReply,false},
				{L7P_XMPP_STREAM,L7_XMPP,IsXMPPStream,false},
				{L7P_XMPP_PROCEED,L7_XMPP,IsXMPPProceedTLS,false},
				{L7P_XMPP_FEATURES,L7_XMPP,IsXMPPFeatures,false}
			};
			protocol_probe(testers, sizeof(testers) / sizeof(*testers), dis->data_payload, dis->len_payload, ctrack, &l7proto, &l7payload);

			if (l7payload==L7P_TLS_SERVER_HELLO)
				TLSDebug(dis->data_payload, dis->len_payload);
		}

		// process reply packets for auto hostlist mode
		// by looking at RSTs or HTTP replies we decide whether original request looks like DPI blocked
		// we only process first-sequence replies. do not react to subsequent redirects or RSTs
		if (!params.server && ctrack && ctrack->hostname_ah_check && !ctrack->failure_detect_finalized && dp->hostlist_auto_incoming_maxseq)
		{
			uint32_t rseq = ctrack->pos.server.seq_last - ctrack->pos.server.seq0;
			if (rseq)
			{
				char client_ip_port[48];
				fill_client_ip_port((struct sockaddr*)&dst, client_ip_port, sizeof(client_ip_port));
				if (seq_within(ctrack->pos.server.seq_last, ctrack->pos.server.seq0 + 1, ctrack->pos.server.seq0 + dp->hostlist_auto_incoming_maxseq))
				{
					bool bFail = false;

					if (dis->tcp->th_flags & TH_RST)
					{
						DLOG("incoming RST detected for hostname %s rseq %u\n", ctrack->hostname, rseq);
						HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : rseq %u : incoming RST", ctrack->hostname, ctrack->dp->n, PROFILE_NAME(dp), client_ip_port, l7proto_str(l7proto), rseq);
						bFail = true;
					}
					else if (dis->len_payload && l7payload == L7P_HTTP_REPLY)
					{
						DLOG("incoming HTTP reply detected for hostname %s rseq %u\n", ctrack->hostname, rseq);
						bFail = HttpReplyLooksLikeDPIRedirect(dis->data_payload, dis->len_payload, ctrack->hostname);
						if (bFail)
						{
							DLOG("redirect to another domain detected. possibly DPI redirect.\n");
							HOSTLIST_DEBUGLOG_APPEND("%s : profile %u (%s) : client %s : proto %s : rseq %u : redirect to another domain", ctrack->hostname, ctrack->dp->n, PROFILE_NAME(dp), client_ip_port, l7proto_str(l7proto), rseq);
						}
						else
							DLOG("local or in-domain redirect detected. it's not a DPI redirect.\n");
					}
					if (bFail)
					{
						auto_hostlist_failed(dp, ctrack->hostname, ctrack->hostname_is_ip, client_ip_port, l7proto);
						ctrack->failure_detect_finalized = true;
					}
				}
				else
				{
					// incoming_maxseq exceeded. treat connection as successful
					auto_hostlist_reset_fail_counter(dp, ctrack->hostname, client_ip_port, l7proto);
					ctrack->failure_detect_finalized = true;
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
			rdata_payload = ctrack_replay->reasm_client.packet;
			rlen_payload = ctrack_replay->reasm_client.size_present;
		}
		else if (reasm_client_feed(ctrack, IPPROTO_TCP, dis->data_payload, dis->len_payload))
		{
			rdata_payload = ctrack->reasm_client.packet;
			rlen_payload = ctrack->reasm_client.size_present;
		}

		process_retrans_fail(ctrack, dis, (struct sockaddr*)&src, ifin);
		if (IsHttp(rdata_payload, rlen_payload))
		{
			DLOG("packet contains HTTP request\n");
			l7payload = L7P_HTTP_REQ;
			if (l7proto == L7_UNKNOWN)
			{
				l7proto = L7_HTTP;
				if (ctrack && ctrack->l7proto == L7_UNKNOWN) ctrack->l7proto = l7proto;
			}

			// we do not reassemble http
			reasm_client_cancel(ctrack);

			bHaveHost = HttpExtractHost(rdata_payload, rlen_payload, host, sizeof(host));
			if (!bHaveHost)
			{
				DLOG("not applying tampering to HTTP without Host:\n");
				goto pass;
			}
		}
		else if (IsTLSClientHello(rdata_payload, rlen_payload, TLS_PARTIALS_ENABLE))
		{
			bool bReqFull = IsTLSRecordFull(rdata_payload, rlen_payload);
			DLOG(bReqFull ? "packet contains full TLS ClientHello\n" : "packet contains partial TLS ClientHello\n");
			l7payload = L7P_TLS_CLIENT_HELLO;
			if (l7proto == L7_UNKNOWN)
			{
				l7proto = L7_TLS;
				if (ctrack && ctrack->l7proto == L7_UNKNOWN) ctrack->l7proto = l7proto;
			}

			if (bReqFull) TLSDebug(rdata_payload, rlen_payload);

			bHaveHost = TLSHelloExtractHost(rdata_payload, rlen_payload, host, sizeof(host), TLS_PARTIALS_ENABLE);
			if (ctrack && !(params.reasm_payload_disable && l7_payload_match(l7payload, params.reasm_payload_disable)))
			{
				// do not reasm retransmissions
				if (!bReqFull && ReasmIsEmpty(&ctrack->reasm_client) && !is_retransmission(&ctrack->pos.client))
				{
					// do not reconstruct unexpected large payload (they are feeding garbage ?)
					if (!reasm_client_start(ctrack, IPPROTO_TCP, TLSRecordLen(dis->data_payload), TCP_MAX_REASM, dis->data_payload, dis->len_payload))
						goto pass_reasm_cancel;
				}

				if (!ReasmIsEmpty(&ctrack->reasm_client))
				{
					if (rawpacket_queue_csum_fix(&ctrack->delayed, dis, &ctrack->pos, &dst, fwmark, desync_fwmark, ifin, ifout))
					{
						DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ctrack->delayed));
					}
					else
					{
						DLOG_ERR("rawpacket_queue failed !\n");
						goto pass_reasm_cancel;
					}
					if (ReasmIsFull(&ctrack->reasm_client))
					{
						replay_queue(&ctrack->delayed);
						reasm_client_fin(ctrack);
					}
					return VERDICT_DROP;
				}
			}
		}
		else if (ctrack && (ctrack->pos.client.seq_last - ctrack->pos.client.seq0)==1 && IsMTProto(dis->data_payload, dis->len_payload))
		{
			DLOG("packet contains telegram mtproto2 initial\n");
			// mtproto detection requires aes. react only on the first tcp data packet. do not detect if ctrack unavailable.
			l7payload = L7P_MTPROTO_INITIAL;
			if (l7proto == L7_UNKNOWN)
			{
				l7proto = L7_MTPROTO;
				if (ctrack->l7proto == L7_UNKNOWN) ctrack->l7proto = l7proto;
			}
		}
		else
		{
			t_protocol_probe testers[] = {
				{L7P_XMPP_STREAM,L7_XMPP,IsXMPPStream,false},
				{L7P_XMPP_STARTTLS,L7_XMPP,IsXMPPStartTLS,false}
			};
			protocol_probe(testers, sizeof(testers) / sizeof(*testers), dis->data_payload, dis->len_payload, ctrack, &l7proto, &l7payload);
		}

	}

	if (bHaveHost)
	{
		bHostIsIp = strip_host_to_ip(host);
		DLOG("hostname: %s\n", host);
	}

	bool bDiscoveredL7;
	if (ctrack_replay)
	{
		if ((bDiscoveredL7 = !ctrack_replay->l7proto_discovered && ctrack_replay->l7proto != L7_UNKNOWN))
			ctrack_replay->l7proto_discovered = true;
	}
	else
		bDiscoveredL7 = l7proto != L7_UNKNOWN;
	if (bDiscoveredL7) DLOG("discovered l7 protocol\n");

	bool bDiscoveredHostname = bHaveHost && !(ctrack_replay && ctrack_replay->hostname_discovered);
	if (bDiscoveredHostname)
	{
		DLOG("discovered hostname\n");
		if (ctrack_replay)
		{
			free(ctrack_replay->hostname);
			ctrack_replay->hostname = strdup(host);
			ctrack_replay->hostname_is_ip = bHostIsIp;
			if (!ctrack_replay->hostname)
			{
				DLOG_ERR("hostname dup : out of memory");
				goto pass_reasm_cancel;
			}
			ctrack_replay->hostname_discovered = true;
			if (!ipcache_put_hostname(sdip4, sdip6, host, bHostIsIp))
				goto pass_reasm_cancel;
			}
	}

	if (bDiscoveredL7 || bDiscoveredHostname)
	{
		struct desync_profile *dp_prev = dp;
		// search for desync profile again. it may have changed.
		dp = dp_find(&params.desync_profiles, IPPROTO_TCP, sdip4, sdip6, sdport,
			ctrack_replay ? ctrack_replay->hostname : bHaveHost ? host : NULL,
			ctrack_replay ? ctrack_replay->hostname_is_ip : bHostIsIp,
			l7proto, ssid,
			&bCheckDone, &bCheckResult, &bCheckExcluded);
		if (ctrack_replay)
		{
			ctrack_replay->dp = dp;
			ctrack_replay->dp_search_complete = true;
			ctrack_replay->bCheckDone = bCheckDone;
			ctrack_replay->bCheckResult = bCheckResult;
			ctrack_replay->bCheckExcluded = bCheckExcluded;
		}
		if (!dp) goto pass_reasm_cancel;
		if (dp != dp_prev)
		{
			dp_changed(ctrack_replay);
			DLOG("desync profile changed by revealed l7 protocol or hostname !\n");
		}
	}
	if (bHaveHost && !PROFILE_HOSTLISTS_EMPTY(dp))
	{
		if (!bCheckDone)
		{
			bCheckResult = HostlistCheck(dp, host, bHostIsIp, &bCheckExcluded, false);
			bCheckDone = true;
			if (ctrack_replay)
			{
				ctrack_replay->bCheckDone = bCheckDone;
				ctrack_replay->bCheckResult = bCheckResult;
				ctrack_replay->bCheckExcluded = bCheckExcluded;
			}
		}
		if (bCheckResult)
			ctrack_stop_retrans_counter(ctrack_replay);
		else
		{
			if (ctrack_replay)
			{
				ctrack_replay->hostname_ah_check = dp->hostlist_auto && !bCheckExcluded;
				if (!ctrack_replay->hostname_ah_check)
					ctrack_stop_retrans_counter(ctrack_replay);
			}
		}
	}

	if (bCheckDone && !bCheckResult)
	{
		DLOG("not applying tampering because of previous negative hostlist check\n");
		goto pass_reasm_cancel;
	}
	if (params.debug)
	{
		char s1[48], s2[48];
		ntop46_port((struct sockaddr *)&src, s1, sizeof(s1));
		ntop46_port((struct sockaddr *)&dst, s2, sizeof(s2));
		DLOG("dpi desync src=%s dst=%s track_direction=%s fixed_direction=%s connection_proto=%s payload_type=%s\n", s1, s2, bReverse ? "in" : "out", bReverseFixed ? "in" : "out", l7proto_str(l7proto), l7payload_str(l7payload));
	}
	verdict = desync(dp, fwmark, ifin, ifout, bReverseFixed, ctrack_replay, tpos, l7payload, l7proto, dis, sdip4, sdip6, sdport, mod_pkt, len_mod_pkt, replay_piece, replay_piece_count, reasm_offset, rdata_payload, rlen_payload, NULL, 0);

pass:
	return (!bReverseFixed && (verdict & VERDICT_MASK) == VERDICT_DROP) ? ct_new_postnat_fix(ctrack, dis, mod_pkt, len_mod_pkt) : verdict;
pass_reasm_cancel:
	reasm_client_cancel(ctrack);
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
		{L7P_DISCORD_IP_DISCOVERY,L7_DISCORD,IsDiscordIpDiscoveryRequest,false},
		{L7P_STUN,L7_STUN,IsStunMessage,false},
		{L7P_DNS_QUERY,L7_DNS,IsDNSQuery,false},
		{L7P_DNS_RESPONSE,L7_DNS,IsDNSResponse,false},
		{L7P_DHT,L7_DHT,IsDht,false},
		{L7P_DTLS_CLIENT_HELLO,L7_DTLS,IsDTLSClientHello,false},
		{L7P_DTLS_SERVER_HELLO,L7_DTLS,IsDTLSServerHello,false},
		{L7P_WIREGUARD_INITIATION,L7_WIREGUARD,IsWireguardHandshakeInitiation,false},
		{L7P_WIREGUARD_RESPONSE,L7_WIREGUARD,IsWireguardHandshakeResponse,false},
		{L7P_WIREGUARD_COOKIE,L7_WIREGUARD,IsWireguardHandshakeCookie,false},
		{L7P_WIREGUARD_KEEPALIVE,L7_WIREGUARD,IsWireguardKeepalive,false},
		{L7P_WIREGUARD_DATA,L7_WIREGUARD,IsWireguardData,true}};

	protocol_probe(testers, sizeof(testers) / sizeof(*testers), data_payload, len_payload, ctrack, l7proto, l7payload);
}


static uint8_t dpi_desync_udp_packet_play(
	unsigned int replay_piece, unsigned int replay_piece_count, size_t reasm_offset,
	uint32_t fwmark,
	const char *ifin, const char *ifout,
	const t_ctrack_positions *tpos,
	const struct dissect *dis,
	uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	uint8_t verdict = VERDICT_PASS;

	// additional safety check
	if (!!dis->ip == !!dis->ip6) return verdict;

	struct desync_profile *dp = NULL;
	t_ctrack *ctrack = NULL, *ctrack_replay = NULL;
	bool bReverse = false, bReverseFixed;
	struct sockaddr_storage src, dst;
	const struct in_addr *sdip4;
	const struct in6_addr *sdip6;
	uint16_t sdport;
	char host[256];
	t_l7proto l7proto = L7_UNKNOWN;
	t_l7payload l7payload = dis->len_payload ? L7P_UNKNOWN : L7P_EMPTY;
	const char *ifname = NULL, *ssid = NULL;

	uint8_t defrag[UDP_MAX_REASM];
	uint8_t *data_decrypt = NULL;
	size_t len_decrypt = 0;

	extract_endpoints(dis->ip, dis->ip6, NULL, dis->udp, &src, &dst);
	sdport = saport((struct sockaddr *)&dst);
	if (dis->ip6)
	{
		sdip4 = NULL;
		sdip6 = params.server ? &dis->ip6->ip6_src : &dis->ip6->ip6_dst;
	}
	else if (dis->ip)
	{
		sdip6 = NULL;
		sdip4 = params.server ? &dis->ip->ip_src : &dis->ip->ip_dst;
	}
	else
		return verdict; // should never happen

	if (replay_piece_count)
	{
		// in replay mode conntrack_replay is not NULL and ctrack is NULL

		//ConntrackPoolDump(&params.conntrack);
		if (!ConntrackPoolDoubleSearch(&params.conntrack, dis, &ctrack_replay, &bReverse) || bReverse)
			return verdict;
		bReverseFixed = bReverse ^ params.server;
		setup_direction(dis, bReverseFixed, &src, &dst, &sdip4, &sdip6, &sdport);

		ifname = bReverse ? ifin : ifout;
#ifdef HAS_FILTER_SSID
		ssid = wlan_ssid_search_ifname(ifname);
		if (ssid) DLOG("found ssid for %s : %s\n", ifname, ssid);
#endif
		l7proto = ctrack_replay->l7proto;
		dp = ctrack_replay->dp;
		if (dp)
			DLOG("using cached desync profile %u (%s)\n", dp->n, PROFILE_NAME(dp));
		else if (!ctrack_replay->dp_search_complete)
		{
			dp = ctrack_replay->dp = dp_find(&params.desync_profiles, IPPROTO_UDP, sdip4, sdip6, sdport, ctrack_replay->hostname, ctrack_replay->hostname_is_ip, l7proto, ssid, NULL, NULL, NULL);
			ctrack_replay->dp_search_complete = true;
		}
		if (!dp)
		{
			DLOG("matching desync profile not found\n");
			return verdict;
		}
	}
	else
	{
		// in real mode ctrack may be NULL or not NULL, conntrack_replay is equal to ctrack

		if (!params.ctrack_disable)
		{
			ConntrackPoolPurge(&params.conntrack);
			if (ConntrackPoolFeed(&params.conntrack, dis, &ctrack, &bReverse))
			{
				dp = ctrack->dp;
				ctrack_replay = ctrack;
			}
		}
		// in absence of conntrack guess direction by presence of interface names. won't work on BSD
		bReverseFixed = ctrack ? (bReverse ^ params.server) : (bReverse = ifin && ifin && (!ifout || !*ifout));
		setup_direction(dis, bReverseFixed, &src, &dst, &sdip4, &sdip6, &sdport);

		ifname = bReverse ? ifin : ifout;
#ifdef HAS_FILTER_SSID
		ssid = wlan_ssid_search_ifname(ifname);
		if (ssid) DLOG("found ssid for %s : %s\n", ifname, ssid);
#endif
		if (ctrack) l7proto = ctrack->l7proto;
		if (dp)
			DLOG("using cached desync profile %u (%s)\n", dp->n, PROFILE_NAME(dp));
		else if (!ctrack || !ctrack->dp_search_complete)
		{
			const char *hostname = NULL;
			bool hostname_is_ip = false;
			if (ctrack)
			{
				hostname = ctrack->hostname;
				hostname_is_ip = ctrack->hostname_is_ip;
				if (!hostname && !bReverse)
				{
					if (ipcache_get_hostname(sdip4, sdip6, host, sizeof(host), &hostname_is_ip) && *host)
						if (!(hostname = ctrack->hostname = strdup(host)))
							DLOG_ERR("strdup(host): out of memory\n");
				}
			}
			dp = dp_find(&params.desync_profiles, IPPROTO_UDP, sdip4, sdip6, sdport, hostname, hostname_is_ip, l7proto, ssid, NULL, NULL, NULL);
			if (ctrack)
			{
				ctrack->dp = dp;
				ctrack->dp_search_complete = true;
			}
		}
		if (!dp)
		{
			DLOG("matching desync profile not found\n");
			return verdict;
		}

		HostFailPoolPurgeRateLimited(&dp->hostlist_auto_fail_counters);
		//ConntrackPoolDump(&params.conntrack);

		if (bReverseFixed)
		{
			if (ctrack && !ctrack->incoming_ttl)
			{
				ctrack->incoming_ttl = ttl46(dis->ip, dis->ip6);
				DLOG("incoming TTL %u\n", ctrack->incoming_ttl);
			}
			ipcache_update_ttl(ctrack, sdip4, sdip6, ifin);
		}
		else
			ipcache_get_ttl(ctrack, sdip4, sdip6, ifout);
	}

	uint32_t desync_fwmark = fwmark | params.desync_fwmark;

	bool bCheckDone, bCheckResult, bCheckExcluded;
	if (ctrack_replay)
	{
		bCheckDone = ctrack_replay->bCheckDone;
		bCheckResult = ctrack_replay->bCheckResult;
		bCheckExcluded = ctrack_replay->bCheckExcluded;
	}
	else
		bCheckDone = bCheckResult = bCheckExcluded = false;


	if (dis->len_payload)
	{
		bool bHaveHost = false, bHostIsIp = false;
		if (bReverse)
		{
			udp_standard_protocol_probe(dis->data_payload, dis->len_payload, ctrack, &l7proto, &l7payload);
		}
		else
		{
			struct blob_collection_head *fake;
			if (IsQUICInitial(dis->data_payload, dis->len_payload))
			{
				DLOG("packet contains QUIC initial\n");
				l7payload = L7P_QUIC_INITIAL;

				l7proto = L7_QUIC;
				// update ctrack l7proto here because reasm can happen
				if (ctrack && ctrack->l7proto == L7_UNKNOWN) ctrack->l7proto = l7proto;

				uint8_t clean[UDP_MAX_REASM], *pclean;
				size_t clean_len;

				if (replay_piece_count)
				{
					clean_len = ctrack_replay->reasm_client.size_present;
					pclean = ctrack_replay->reasm_client.packet;
				}
				else
				{
					clean_len = sizeof(clean);
					pclean = QUICDecryptInitial(dis->data_payload, dis->len_payload, clean, &clean_len) ? clean : NULL;
				}
				if (pclean)
				{
					bool reasm_disable = params.reasm_payload_disable && l7_payload_match(l7payload, params.reasm_payload_disable);
					if (ctrack && !reasm_disable && !ReasmIsEmpty(&ctrack->reasm_client))
					{
						if (ReasmHasSpace(&ctrack->reasm_client, clean_len))
						{
							reasm_client_feed(ctrack, IPPROTO_UDP, clean, clean_len);
							pclean = ctrack->reasm_client.packet;
							clean_len = ctrack->reasm_client.size_present;
						}
						else
						{
							DLOG("QUIC reasm is too long. cancelling.\n");
							goto pass_reasm_cancel;
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

							if (ctrack && !reasm_disable)
							{
								if (bIsHello && !bReqFull && ReasmIsEmpty(&ctrack->reasm_client))
								{
									// preallocate max buffer to avoid reallocs that cause memory copy
									if (!reasm_client_start(ctrack, IPPROTO_UDP, UDP_MAX_REASM, UDP_MAX_REASM, clean, clean_len))
										goto pass_reasm_cancel;
								}
								if (!ReasmIsEmpty(&ctrack->reasm_client))
								{
									if (rawpacket_queue_csum_fix(&ctrack->delayed, dis, &ctrack->pos, &dst, fwmark, desync_fwmark, ifin, ifout))
									{
										DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ctrack->delayed));
									}
									else
									{
										DLOG_ERR("rawpacket_queue failed !\n");
										goto pass_reasm_cancel;
									}
									if (bReqFull)
									{
										replay_queue(&ctrack->delayed);
										reasm_client_fin(ctrack);
									}
									return ct_new_postnat_fix(ctrack, dis, mod_pkt, len_mod_pkt);
								}
							}

							if (bIsHello)
							{
								data_decrypt = defrag + hello_offset;
								len_decrypt = hello_len;
								bHaveHost = TLSHelloExtractHostFromHandshake(data_decrypt, len_decrypt, host, sizeof(host), TLS_PARTIALS_ENABLE);
							}
							else
							{
								quic_reasm_cancel(ctrack, "QUIC initial without ClientHello");
							}
						}
						else
						{
							DLOG("QUIC initial contains CRYPTO with partial fragment coverage\n");
							if (ctrack && !reasm_disable)
							{
								if (ReasmIsEmpty(&ctrack->reasm_client))
								{
									// preallocate max buffer to avoid reallocs that cause memory copy
									if (!reasm_client_start(ctrack, IPPROTO_UDP, UDP_MAX_REASM, UDP_MAX_REASM, clean, clean_len))
										goto pass_reasm_cancel;
								}
								if (rawpacket_queue_csum_fix(&ctrack->delayed, dis, &ctrack->pos, &dst, fwmark, desync_fwmark, ifin, ifout))
								{
									DLOG("DELAY desync until reasm is complete (#%u)\n", rawpacket_queue_count(&ctrack->delayed));
								}
								else
								{
									DLOG_ERR("rawpacket_queue failed !\n");
									goto pass_reasm_cancel;
								}
								return ct_new_postnat_fix(ctrack, dis, mod_pkt, len_mod_pkt);
							}
							quic_reasm_cancel(ctrack, "QUIC initial fragmented CRYPTO");
						}
					}
					else
					{
						// defrag failed
						quic_reasm_cancel(ctrack, "QUIC initial defrag CRYPTO failed");
					}
				}
				else
				{
					// decrypt failed
					quic_reasm_cancel(ctrack, "QUIC initial decryption failed");
				}
			}
			else // not QUIC initial
			{
				// not quic initial - stop reasm
				reasm_client_cancel(ctrack);

				udp_standard_protocol_probe(dis->data_payload, dis->len_payload, ctrack, &l7proto, &l7payload);
			}
		}

		if (bHaveHost)
		{
			bHostIsIp = strip_host_to_ip(host);
			DLOG("hostname: %s\n", host);
		}

		bool bDiscoveredL7;
		if (ctrack_replay)
		{
			if ((bDiscoveredL7 = !ctrack_replay->l7proto_discovered && l7proto != L7_UNKNOWN))
				ctrack_replay->l7proto_discovered = true;
		}
		else
			bDiscoveredL7 = l7proto != L7_UNKNOWN;
		if (bDiscoveredL7) DLOG("discovered l7 protocol\n");

		bool bDiscoveredHostname = bHaveHost && !(ctrack_replay && ctrack_replay->hostname_discovered);
		if (bDiscoveredHostname)
		{
			DLOG("discovered hostname\n");
			if (ctrack_replay)
			{
				ctrack_replay->hostname_discovered = true;
				free(ctrack_replay->hostname);
				ctrack_replay->hostname = strdup(host);
				ctrack_replay->hostname_is_ip = bHostIsIp;
				if (!ctrack_replay->hostname)
				{
					DLOG_ERR("hostname dup : out of memory");
					goto pass;
				}
				if (!ipcache_put_hostname(sdip4, sdip6, host, bHostIsIp))
					goto pass;
			}
		}

		if (bDiscoveredL7 || bDiscoveredHostname)
		{
			struct desync_profile *dp_prev = dp;

			// search for desync profile again. it may have changed.
			dp = dp_find(&params.desync_profiles, IPPROTO_UDP, sdip4, sdip6, sdport,
				ctrack_replay ? ctrack_replay->hostname : bHaveHost ? host : NULL,
				ctrack_replay ? ctrack_replay->hostname_is_ip : bHostIsIp,
				l7proto, ssid,
				&bCheckDone, &bCheckResult, &bCheckExcluded);
			if (ctrack_replay)
			{
				ctrack_replay->dp = dp;
				ctrack_replay->dp_search_complete = true;
				ctrack_replay->bCheckDone = bCheckDone;
				ctrack_replay->bCheckResult = bCheckResult;
				ctrack_replay->bCheckExcluded = bCheckExcluded;
			}
			if (!dp)
				goto pass_reasm_cancel;
			if (dp != dp_prev)
			{
				dp_changed(ctrack_replay);
				DLOG("desync profile changed by revealed l7 protocol or hostname !\n");
			}
		}
		else if (ctrack_replay)
		{
			bCheckDone = ctrack_replay->bCheckDone;
			bCheckResult = ctrack_replay->bCheckResult;
			bCheckExcluded = ctrack_replay->bCheckExcluded;
		}

		if (bHaveHost && !PROFILE_HOSTLISTS_EMPTY(dp))
		{
			if (!bCheckDone)
			{
				bCheckResult = HostlistCheck(dp, host, bHostIsIp, &bCheckExcluded, false);
				bCheckDone = true;
				if (ctrack_replay)
				{
					ctrack_replay->bCheckDone = bCheckDone;
					ctrack_replay->bCheckResult = bCheckResult;
					ctrack_replay->bCheckExcluded = bCheckExcluded;
				}
			}
			if (!bCheckResult && ctrack_replay)
				ctrack_replay->hostname_ah_check = dp->hostlist_auto && !bCheckExcluded;
		}

		process_udp_fail(ctrack_replay, tpos, (struct sockaddr*)&src);
	} // len_payload

	if (bCheckDone && !bCheckResult)
	{
		DLOG("not applying tampering because of negative hostlist check\n");
		goto pass_reasm_cancel;
	}
	if (params.debug)
	{
		char s1[48], s2[48];
		ntop46_port((struct sockaddr *)&src, s1, sizeof(s1));
		ntop46_port((struct sockaddr *)&dst, s2, sizeof(s2));
		DLOG("dpi desync src=%s dst=%s track_direction=%s fixed_direction=%s connection_proto=%s payload_type=%s\n", s1, s2, bReverse ? "in" : "out", bReverseFixed ? "in" : "out", l7proto_str(l7proto), l7payload_str(l7payload));
	}
	verdict = desync(dp, fwmark, ifin, ifout, bReverseFixed, ctrack_replay, tpos, l7payload, l7proto, dis, sdip4, sdip6, sdport, mod_pkt, len_mod_pkt, replay_piece, replay_piece_count, reasm_offset, NULL, 0, data_decrypt, len_decrypt);

pass:
	return (!bReverse && (verdict & VERDICT_MASK) == VERDICT_DROP) ? ct_new_postnat_fix(ctrack, dis, mod_pkt, len_mod_pkt) : verdict;
pass_reasm_cancel:
	reasm_client_cancel(ctrack);
	goto pass;
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
			if (dis->len_payload) { DLOG("TCP: len=%zu : ", dis->len_payload); hexdump_limited_dlog(dis->data_payload, dis->len_payload, PKTDATA_MAXDUMP); DLOG("\n"); }
		}
		else if (dis->udp)
		{
			char s[30];
			str_udphdr(s, sizeof(s), dis->udp);
			DLOG(" %s\n", s);
			if (dis->len_payload) { DLOG("UDP: len=%zu : ", dis->len_payload); hexdump_limited_dlog(dis->data_payload, dis->len_payload, PKTDATA_MAXDUMP); DLOG("\n"); }
		}
		else
			DLOG("\n");
	}
}


static uint8_t dpi_desync_packet_play(
	unsigned int replay_piece, unsigned int replay_piece_count, size_t reasm_offset, uint32_t fwmark, const char *ifin, const char *ifout,
	const t_ctrack_positions *tpos,
	const uint8_t *data_pkt, size_t len_pkt,
	uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	struct dissect dis;
	uint8_t verdict = VERDICT_PASS;

	proto_dissect_l3l4(data_pkt, len_pkt, &dis);
	if (!!dis.ip != !!dis.ip6)
	{
		packet_debug(!!replay_piece_count, &dis);
		switch (dis.proto)
		{
		case IPPROTO_TCP:
			if (dis.tcp)
			{
				verdict = dpi_desync_tcp_packet_play(replay_piece, replay_piece_count, reasm_offset, fwmark, ifin, ifout, tpos, &dis, mod_pkt, len_mod_pkt);
				// we fix csum before pushing to replay queue
				if (!replay_piece_count) verdict_tcp_csum_fix(verdict, (struct tcphdr *)dis.tcp, dis.transport_len, dis.ip, dis.ip6);
			}
			break;
		case IPPROTO_UDP:
			if (dis.udp)
			{
				verdict = dpi_desync_udp_packet_play(replay_piece, replay_piece_count, reasm_offset, fwmark, ifin, ifout, tpos, &dis, mod_pkt, len_mod_pkt);
				// we fix csum before pushing to replay queue
				if (!replay_piece_count) verdict_udp_csum_fix(verdict, (struct udphdr *)dis.udp, dis.transport_len, dis.ip, dis.ip6);
			}
			break;
		}
	}
	return verdict;
}
uint8_t dpi_desync_packet(uint32_t fwmark, const char *ifin, const char *ifout, const uint8_t *data_pkt, size_t len_pkt, uint8_t *mod_pkt, size_t *len_mod_pkt)
{
	ipcachePurgeRateLimited(&params.ipcache, params.ipcache_lifetime);
	return dpi_desync_packet_play(0, 0, 0, fwmark, ifin, ifout, NULL, data_pkt, len_pkt, mod_pkt, len_mod_pkt);
}



static bool replay_queue(struct rawpacket_tailhead *q)
{
	struct rawpacket *rp;
	size_t offset;
	unsigned int i, count;
	bool b = true;
	uint8_t mod[RECONSTRUCT_MAX_SIZE];
	size_t modlen;

	for (i = 0, offset = 0, count = rawpacket_queue_count(q); (rp = rawpacket_dequeue(q)); offset += rp->len_payload, rawpacket_free(rp), i++)
	{
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
	}
	return b;
}
