#pragma once

#include <stdint.h>
#include <time.h>

#define CTRACK_T_SYN	60
#define CTRACK_T_FIN	60
#define CTRACK_T_EST	300
#define CTRACK_T_UDP	60

// SYN - SYN or SYN/ACK received
// ESTABLISHED - any except SYN or SYN/ACK received
// FIN - FIN or RST received
typedef enum {SYN=0, ESTABLISHED, FIN} t_connstate;

typedef struct
{
	uint64_t pcounter;	// packet counter
	uint64_t pdcounter;	// data packet counter (with payload)
	uint64_t pbcounter;	// transferred byte counter. includes retransmissions. it's not the same as relative seq.
	uint32_t ip6flow;

	// tcp only state, not used in udp
	uint32_t pos;		// TCP: seq_last+payload, ack_last+payload  UDP: sum of all seen payload lenghts including current
	uint32_t uppos;		// max seen position. useful to detect retransmissions
	uint32_t uppos_prev; 	// previous max seen position. useful to detect retransmissions
	uint32_t seq_last;	// TCP: last seen seq and ack  UDP: sum of all seen payload lenghts NOT including current
	uint32_t seq0;		// starting seq and ack
	uint16_t winsize;	// last seen window size
	uint16_t mss;
	uint32_t winsize_calc;	// calculated window size
	uint8_t scale;		// last seen window scale factor. SCALE_NONE if none
	bool rseq_over_2G;
} t_ctrack_position;

typedef struct
{
	struct timespec t_last;
	t_connstate state;
	t_ctrack_position client, server;
}
t_ctrack_positions;
