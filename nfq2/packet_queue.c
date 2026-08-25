#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "packet_queue.h"

void rawpacket_queue_init(struct rawpacket_queue *q, unsigned int max_packets)
{
	TAILQ_INIT(&q->q);
	q->max_packets = max_packets;
}
void rawpacket_free(struct rawpacket *rp)
{
	if (rp) free(rp->packet);
	free(rp);
}
struct rawpacket *rawpacket_dequeue(struct rawpacket_queue *q)
{
	struct rawpacket *rp;
	rp = TAILQ_FIRST(&q->q);
	if (rp)	TAILQ_REMOVE(&q->q, rp, next);
	return rp;
}
void rawpacket_queue_destroy(struct rawpacket_queue *q)
{
	struct rawpacket *rp;
	while((rp = rawpacket_dequeue(q))) rawpacket_free(rp);
}

struct rawpacket *rawpacket_queue(
	struct rawpacket_queue *q,
	const struct sockaddr_storage* dst,
	uint32_t fwmark_orig, uint32_t fwmark,
	const char *ifin, const char *ifout,
	const void *data, size_t len, size_t len_payload,
	const t_ctrack_positions *tpos,
	bool server_side)
{
	if (q->max_packets && rawpacket_queue_count(q)>=q->max_packets) return NULL;

	struct rawpacket *rp = malloc(sizeof(struct rawpacket));
	if (!rp) return NULL;

	rp->packet = malloc(len);
	if (!rp->packet)
	{
		free(rp);
		return NULL;
	}

	rp->dst = *dst;
	rp->fwmark_orig = fwmark_orig;
	rp->fwmark = fwmark;
	if (ifin)
		snprintf(rp->ifin,sizeof(rp->ifin),"%s",ifin);
	else
		*rp->ifin = 0;
	if (ifout)
		snprintf(rp->ifout,sizeof(rp->ifout),"%s",ifout);
	else
		*rp->ifout = 0;
	memcpy(rp->packet,data,len);
	rp->len=len;
	rp->len_payload=len_payload;

	// make a copy for replay
	if (tpos)
	{
		rp->tpos = *tpos;
		rp->tpos_present = true;
	}
	else
		rp->tpos_present = false;
	rp->server_side = server_side;
	rp->suppress_replay_send = false;

	TAILQ_INSERT_TAIL(&q->q, rp, next);
	
	return rp;
}

unsigned int rawpacket_queue_count(const struct rawpacket_queue *q)
{
	const struct rawpacket *rp;
	unsigned int ct=0;
	TAILQ_FOREACH(rp, &q->q, next) ct++;
	return ct;
}
bool rawpacket_queue_empty(const struct rawpacket_queue *q)
{
	return !TAILQ_FIRST(&q->q);
}
