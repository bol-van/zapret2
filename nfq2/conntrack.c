#include "conntrack.h"
#include "darkmagic.h"
#include <arpa/inet.h>
#include <stdio.h>

#include "params.h"
#include "lua.h"

#undef uthash_nonfatal_oom
#define uthash_nonfatal_oom(elt) ut_oom_recover(elt)

static bool oom = false;
static void ut_oom_recover(void *elem)
{
	oom = true;
}

static const char *connstate_s[] = { "SYN","ESTABLISHED","FIN" };

static void connswap(const t_conn *c, t_conn *c2)
{
	memset(c2, 0, sizeof(*c2));
	c2->l3proto = c->l3proto;
	c2->l4proto = c->l4proto;
	c2->src = c->dst;
	c2->dst = c->src;
	c2->sport = c->dport;
	c2->dport = c->sport;
}

void ConntrackClearHostname(t_ctrack *track)
{
	free(track->hostname);
	track->hostname = NULL;
	track->hostname_is_ip = false;
}
static void ConntrackClearTrack(t_ctrack *track)
{
	ConntrackClearHostname(track);
	ReasmClear(&track->reasm_client);
	rawpacket_queue_destroy(&track->delayed);
	luaL_unref(params.L, LUA_REGISTRYINDEX, track->lua_state);
	luaL_unref(params.L, LUA_REGISTRYINDEX, track->lua_instance_cutoff);
}

static void ConntrackFreeElem(t_conntrack_pool *elem)
{
	ConntrackClearTrack(&elem->track);
	free(elem);
}

static void ConntrackPoolDestroyPool(t_conntrack_pool **pp)
{
	t_conntrack_pool *elem, *tmp;
	HASH_ITER(hh, *pp, elem, tmp) { HASH_DEL(*pp, elem); ConntrackFreeElem(elem); }
}
void ConntrackPoolDestroy(t_conntrack *p)
{
	ConntrackPoolDestroyPool(&p->pool);
}

void ConntrackPoolInit(t_conntrack *p, time_t purge_interval, uint32_t timeout_syn, uint32_t timeout_established, uint32_t timeout_fin, uint32_t timeout_udp)
{
	p->timeout_syn = timeout_syn;
	p->timeout_established = timeout_established;
	p->timeout_fin = timeout_fin;
	p->timeout_udp = timeout_udp;
	p->t_purge_interval = purge_interval;
	time(&p->t_last_purge);
	p->pool = NULL;
}

void ConntrackExtractConn(t_conn *c, bool bReverse, const struct dissect *dis)
{
	memset(c, 0, sizeof(*c));
	if (dis->ip)
	{
		c->l3proto = IPPROTO_IP;
		c->dst.ip = bReverse ? dis->ip->ip_src : dis->ip->ip_dst;
		c->src.ip = bReverse ? dis->ip->ip_dst : dis->ip->ip_src;
	}
	else if (dis->ip6)
	{
		c->l3proto = IPPROTO_IPV6;
		c->dst.ip6 = bReverse ? dis->ip6->ip6_src : dis->ip6->ip6_dst;
		c->src.ip6 = bReverse ? dis->ip6->ip6_dst : dis->ip6->ip6_src;
	}
	else
		c->l3proto = -1;
	extract_ports(dis->tcp, dis->udp, &c->l4proto, bReverse ? &c->dport : &c->sport, bReverse ? &c->sport : &c->dport);
}


static t_conntrack_pool *ConntrackPoolSearch(t_conntrack_pool *p, const t_conn *c)
{
	t_conntrack_pool *t;
	HASH_FIND(hh, p, c, sizeof(*c), t);
	return t;
}

static void ConntrackInitTrack(t_ctrack *t)
{
	memset(t, 0, sizeof(*t));
	t->l7proto = L7_UNKNOWN;
	t->pos.client.scale = t->pos.server.scale = SCALE_NONE;
	rawpacket_queue_init(&t->delayed);
	lua_newtable(params.L);
	t->lua_state = luaL_ref(params.L, LUA_REGISTRYINDEX);
	lua_newtable(params.L);
	t->lua_instance_cutoff = luaL_ref(params.L, LUA_REGISTRYINDEX);
}
static void ConntrackReInitTrack(t_ctrack *t)
{
	ConntrackClearTrack(t);
	ConntrackInitTrack(t);
}

static t_conntrack_pool *ConntrackNew(t_conntrack_pool **pp, const t_conn *c)
{
	t_conntrack_pool *ctnew;
	if (!(ctnew = malloc(sizeof(*ctnew)))) return NULL;
	ctnew->conn = *c;
	oom = false;
	HASH_ADD(hh, *pp, conn, sizeof(*c), ctnew);
	if (oom) { free(ctnew); return NULL; }
	ConntrackInitTrack(&ctnew->track);
	return ctnew;
}

static void ConntrackApplyPos(t_ctrack *t, bool bReverse, const struct dissect *dis)
{
	uint8_t scale;
	uint16_t mss;
	t_ctrack_position *direct, *reverse;

	direct = bReverse ? &t->pos.server : &t->pos.client;
	reverse = bReverse ? &t->pos.client : &t->pos.server;

	if (dis->ip6) direct->ip6flow = ntohl(dis->ip6->ip6_ctlun.ip6_un1.ip6_un1_flow);

	scale = tcp_find_scale_factor(dis->tcp);
	mss = ntohs(tcp_find_mss(dis->tcp));

	direct->seq_last = ntohl(dis->tcp->th_seq);
	direct->pos = direct->seq_last + dis->len_payload;
	reverse->pos = reverse->seq_last = ntohl(dis->tcp->th_ack);
	if (t->pos.state == SYN)
		direct->uppos_prev = direct->uppos = direct->pos;
	else if (dis->len_payload)
	{
		direct->uppos_prev = direct->uppos;
		if (!((direct->pos - direct->uppos) & 0x80000000))
			direct->uppos = direct->pos;
	}
	direct->winsize = ntohs(dis->tcp->th_win);
	direct->winsize_calc = direct->winsize;
	if (direct->scale != SCALE_NONE) direct->winsize_calc <<= direct->scale;
	if (mss && !direct->mss) direct->mss = mss;
	if (scale != SCALE_NONE) direct->scale = scale;

	if (!direct->rseq_over_2G && ((direct->seq_last - direct->seq0) & 0x80000000))
		direct->rseq_over_2G = true;
	if (!reverse->rseq_over_2G && ((reverse->seq_last - reverse->seq0) & 0x80000000))
		reverse->rseq_over_2G = true;
}

static void ConntrackFeedPacket(t_ctrack *t, bool bReverse, const struct dissect *dis)
{
	uint8_t scale;
	uint16_t mss;

	if (bReverse)
	{
		t->pos.server.pcounter++;
		t->pos.server.pdcounter += !!dis->len_payload;
		t->pos.server.pbcounter += dis->len_payload;
	}

	else
	{
		t->pos.client.pcounter++;
		t->pos.client.pdcounter += !!dis->len_payload;
		t->pos.client.pbcounter += dis->len_payload;
	}

	if (dis->tcp)
	{
		if (tcp_syn_segment(dis->tcp))
		{
			if (t->pos.state != SYN) ConntrackReInitTrack(t); // erase current entry
			t->pos.client.seq0 = ntohl(dis->tcp->th_seq);
		}
		else if (tcp_synack_segment(dis->tcp))
		{
			// ignore SA dups
			uint32_t seq0 = ntohl(dis->tcp->th_ack) - 1;
			if (t->pos.state != SYN && t->pos.client.seq0 != seq0)
				ConntrackReInitTrack(t); // erase current entry
			if (!t->pos.client.seq0) t->pos.client.seq0 = seq0;
			t->pos.server.seq0 = ntohl(dis->tcp->th_seq);
		}
		else if (dis->tcp->th_flags & (TH_FIN | TH_RST))
		{
			t->pos.state = FIN;
		}
		else
		{
			if (t->pos.state == SYN)
			{
				t->pos.state = ESTABLISHED;
				if (!bReverse && !t->pos.server.seq0) t->pos.server.seq0 = ntohl(dis->tcp->th_ack) - 1;
			}
		}

		ConntrackApplyPos(t, bReverse, dis);
	}

	clock_gettime(CLOCK_REALTIME, &t->pos.t_last);
	// make sure t_start gets exactly the same value as first t_last
	if (!t->t_start.tv_sec) t->t_start = t->pos.t_last;
}

static bool ConntrackPoolDoubleSearchPool(t_conntrack_pool **pp, const struct dissect *dis, t_ctrack **ctrack, bool *bReverse)
{
	t_conn conn, connswp;
	t_conntrack_pool *ctr;

	ConntrackExtractConn(&conn, false, dis);
	if ((ctr = ConntrackPoolSearch(*pp, &conn)))
	{
		if (bReverse) *bReverse = false;
		if (ctrack) *ctrack = &ctr->track;
		return true;
	}
	else
	{
		connswap(&conn, &connswp);
		if ((ctr = ConntrackPoolSearch(*pp, &connswp)))
		{
			if (bReverse) *bReverse = true;
			if (ctrack) *ctrack = &ctr->track;
			return true;
		}
	}
	return false;
}
bool ConntrackPoolDoubleSearch(t_conntrack *p, const struct dissect *dis, t_ctrack **ctrack, bool *bReverse)
{
	return ConntrackPoolDoubleSearchPool(&p->pool, dis, ctrack, bReverse);
}

static bool ConntrackPoolFeedPool(t_conntrack_pool **pp, const struct dissect *dis, t_ctrack **ctrack, bool *bReverse)
{
	t_conn conn, connswp;
	t_conntrack_pool *ctr;
	bool b_rev;
	uint8_t proto = dis->tcp ? IPPROTO_TCP : dis->udp ? IPPROTO_UDP : IPPROTO_NONE;

	ConntrackExtractConn(&conn, false, dis);
	if ((ctr = ConntrackPoolSearch(*pp, &conn)))
	{
		ConntrackFeedPacket(&ctr->track, (b_rev = false), dis);
		goto ok;
	}
	else
	{
		connswap(&conn, &connswp);
		if ((ctr = ConntrackPoolSearch(*pp, &connswp)))
		{
			ConntrackFeedPacket(&ctr->track, (b_rev = true), dis);
			goto ok;
		}
	}
	b_rev = dis->tcp && tcp_synack_segment(dis->tcp);
	if ((dis->tcp && tcp_syn_segment(dis->tcp)) || b_rev || dis->udp)
	{
		if ((ctr = ConntrackNew(pp, b_rev ? &connswp : &conn)))
		{
			ConntrackFeedPacket(&ctr->track, b_rev, dis);
			goto ok;
		}
	}
	return false;
ok:
	ctr->track.ipproto = proto;
	if (ctrack) *ctrack = &ctr->track;
	if (bReverse) *bReverse = b_rev;
	return true;
}
bool ConntrackPoolFeed(t_conntrack *p, const struct dissect *dis, t_ctrack **ctrack, bool *bReverse)
{
	return ConntrackPoolFeedPool(&p->pool, dis, ctrack, bReverse);
}

static bool ConntrackPoolDropPool(t_conntrack_pool **pp, const struct dissect *dis)
{
	t_conn conn, connswp;
	t_conntrack_pool *t;
	ConntrackExtractConn(&conn, false, dis);
	if (!(t = ConntrackPoolSearch(*pp, &conn)))
	{
		connswap(&conn, &connswp);
		t = ConntrackPoolSearch(*pp, &connswp);
	}
	if (!t) return false;
	HASH_DEL(*pp, t); ConntrackFreeElem(t);
	return true;
}
bool ConntrackPoolDrop(t_conntrack *p, const struct dissect *dis)
{
	return ConntrackPoolDropPool(&p->pool, dis);
}

void ConntrackPoolPurge(t_conntrack *p)
{
	time_t tidle;
	struct timespec tnow;
	t_conntrack_pool *t, *tmp;

	if (clock_gettime(CLOCK_REALTIME, &tnow)) return;
	if ((tnow.tv_sec - p->t_last_purge) >= p->t_purge_interval)
	{
		HASH_ITER(hh, p->pool, t, tmp) {
			tidle = tnow.tv_sec - t->track.pos.t_last.tv_sec;
			if (t->track.b_cutoff ||
				(t->conn.l4proto == IPPROTO_TCP && (
				(t->track.pos.state == SYN && tidle >= p->timeout_syn) ||
					(t->track.pos.state == ESTABLISHED && tidle >= p->timeout_established) ||
					(t->track.pos.state == FIN && tidle >= p->timeout_fin))
					) || (t->conn.l4proto == IPPROTO_UDP && tidle >= p->timeout_udp)
				)
			{
				HASH_DEL(p->pool, t); ConntrackFreeElem(t);
			}
		}
		p->t_last_purge = tnow.tv_sec;
	}
}

static void taddr2str(uint8_t l3proto, const t_addr *a, char *buf, size_t bufsize)
{
	if (!inet_ntop(family_from_proto(l3proto), a, buf, bufsize) && bufsize) *buf = 0;
}

void ConntrackPoolDump(const t_conntrack *p)
{
	t_conntrack_pool *t, *tmp;
	struct timespec tnow;
	char sa1[40], sa2[40];

	if (clock_gettime(CLOCK_REALTIME, &tnow)) return;
	HASH_ITER(hh, p->pool, t, tmp) {
		taddr2str(t->conn.l3proto, &t->conn.src, sa1, sizeof(sa1));
		taddr2str(t->conn.l3proto, &t->conn.dst, sa2, sizeof(sa2));
		printf("%s [%s]:%u => [%s]:%u : %s : t0=%llu last=t0+%llu now=last+%llu client=d%llu/n%llu/b%llu server=d%llu/n%llu/b%lld ",
			proto_name(t->conn.l4proto),
			sa1, t->conn.sport, sa2, t->conn.dport,
			t->conn.l4proto == IPPROTO_TCP ? connstate_s[t->track.pos.state] : "-",
			(unsigned long long)t->track.t_start.tv_sec, (unsigned long long)(t->track.pos.t_last.tv_sec - t->track.t_start.tv_sec), (unsigned long long)(tnow.tv_sec - t->track.pos.t_last.tv_sec),
			(unsigned long long)t->track.pos.client.pdcounter, (unsigned long long)t->track.pos.client.pcounter, (unsigned long long)t->track.pos.client.pbcounter,
			(unsigned long long)t->track.pos.server.pdcounter, (unsigned long long)t->track.pos.server.pcounter, (unsigned long long)t->track.pos.server.pbcounter);
		if (t->conn.l4proto == IPPROTO_TCP)
			printf("seq0=%u rseq=%u client.pos=%u ack0=%u rack=%u server.pos=%u client.mss=%u server.mss=%u client.wsize=%u:%d server.wsize=%u:%d",
				t->track.pos.client.seq0, t->track.pos.client.seq_last - t->track.pos.client.seq0, t->track.pos.client.pos - t->track.pos.client.seq0,
				t->track.pos.server.seq0, t->track.pos.server.seq_last - t->track.pos.server.seq0, t->track.pos.server.pos - t->track.pos.server.seq0,
				t->track.pos.client.mss, t->track.pos.server.mss,
				t->track.pos.client.winsize, t->track.pos.client.scale == SCALE_NONE ? -1 : t->track.pos.client.scale,
				t->track.pos.server.winsize, t->track.pos.server.scale == SCALE_NONE ? -1 : t->track.pos.server.scale);
		else
			printf("rseq=%u client.pos=%u rack=%u server.pos=%u",
				t->track.pos.client.seq_last, t->track.pos.client.pos,
				t->track.pos.server.seq_last, t->track.pos.server.pos);
		printf(" req_retrans=%u cutoff=%u lua_in_cutoff=%u lua_out_cutoff=%u hostname=%s l7proto=%s\n",
			t->track.req_retrans_counter, t->track.b_cutoff, t->track.b_lua_in_cutoff, t->track.b_lua_out_cutoff, t->track.hostname, l7proto_str(t->track.l7proto));
	};
}


void ReasmClear(t_reassemble *reasm)
{
	free(reasm->packet);
	reasm->packet = NULL;
	reasm->size = reasm->size_present = 0;
}
bool ReasmInit(t_reassemble *reasm, size_t size_requested, uint32_t seq_start)
{
	reasm->packet = malloc(size_requested);
	if (!reasm->packet) return false;
	reasm->size = size_requested;
	reasm->size_present = 0;
	reasm->seq = seq_start;
	return true;
}
bool ReasmResize(t_reassemble *reasm, size_t new_size)
{
	uint8_t *p = realloc(reasm->packet, new_size);
	if (!p) return false;
	reasm->packet = p;
	reasm->size = new_size;
	if (reasm->size_present > new_size) reasm->size_present = new_size;
	return true;
}
#define REASM_MAX_NEG 0x100000
bool ReasmFeed(t_reassemble *reasm, uint32_t seq, const void *payload, size_t len)
{
	uint32_t dseq = seq - reasm->seq;
	if (dseq && (dseq < REASM_MAX_NEG))
		return false; // fail session if a gap about to appear
	uint32_t neg_overlap = reasm->seq - seq;
	if (neg_overlap > REASM_MAX_NEG)
		return false; // too big minus

	size_t szcopy, szignore;
	szignore = (neg_overlap > reasm->size_present) ? neg_overlap - reasm->size_present : 0;
	if (szignore>=len) return true; // everyting is before the starting pos
	szcopy = len - szignore;
	neg_overlap -= szignore;
	if ((reasm->size_present - neg_overlap + szcopy) > reasm->size)
		return false; // buffer overflow
	// in case of seq overlap new data replaces old - unix behavior
	memcpy(reasm->packet + reasm->size_present - neg_overlap, payload + szignore, szcopy);
	if (szcopy>neg_overlap)
	{
		reasm->size_present += szcopy - neg_overlap;
		reasm->seq += (uint32_t)szcopy - neg_overlap;
	}
	return true;
}
bool ReasmHasSpace(t_reassemble *reasm, size_t len)
{
	return (reasm->size_present + len) <= reasm->size;
}
