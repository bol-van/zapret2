#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <net/if.h>
#include <sys/socket.h>

#include "conntrack_base.h"

struct rawpacket
{
	struct sockaddr_storage dst;
	char ifin[IFNAMSIZ], ifout[IFNAMSIZ];
	uint32_t fwmark_orig;
	uint32_t fwmark;
	size_t len, len_payload;
	uint8_t *packet;
	t_ctrack_positions tpos;
	bool tpos_present;
	bool server_side;		// true = reasm of packets from the server side
	bool suppress_replay_send;	// fastpath workaround: first reasm fragment replaced in-flight with ACK-only, never resend it on replay
	TAILQ_ENTRY(rawpacket) next;
};
TAILQ_HEAD(rawpacket_tailhead, rawpacket);

struct rawpacket_queue
{
	struct rawpacket_tailhead q;
	unsigned int max_packets;
};

void rawpacket_queue_init(struct rawpacket_queue *q, unsigned int max_packets);
void rawpacket_queue_destroy(struct rawpacket_queue *q);
bool rawpacket_queue_empty(const struct rawpacket_queue *q);
unsigned int rawpacket_queue_count(const struct rawpacket_queue *q);
struct rawpacket *rawpacket_queue(struct rawpacket_queue *q,const struct sockaddr_storage* dst,uint32_t fwmark_orig,uint32_t fwmark,const char *ifin,const char *ifout,const void *data,size_t len,size_t len_payload,const t_ctrack_positions *tpos,bool server_side);
struct rawpacket *rawpacket_dequeue(struct rawpacket_queue *q);
void rawpacket_free(struct rawpacket *rp);
