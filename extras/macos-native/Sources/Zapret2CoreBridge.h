#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum zapret2_mac_verdict {
	ZAPRET2_MAC_PASS = 0,
	ZAPRET2_MAC_MODIFY = 1,
	ZAPRET2_MAC_DROP = 2,
	ZAPRET2_MAC_ERROR = 255
};

struct zapret2_mac_packet_result {
	enum zapret2_mac_verdict verdict;
	size_t packet_len;
};

/*
 * Initialize the zapret2 core for macOS packet processing.
 *
 * The config file uses the same command-line style accepted by nfqws2/dvtws2.
 * This bridge is intentionally small: the Network Extension adapter owns packet
 * capture, while zapret2 core owns protocol parsing and Lua desync strategies.
 */
int zapret2_mac_core_init(const char *config_file, char *errbuf, size_t errbuf_len);

/*
 * Process one raw IPv4 or IPv6 packet.
 *
 * out_packet may point to the same buffer as packet if the caller provides
 * enough writable space. out_packet_len is both input capacity and output size.
 */
struct zapret2_mac_packet_result zapret2_mac_core_process_packet(
	const uint8_t *packet,
	size_t packet_len,
	const char *ifin,
	const char *ifout,
	uint8_t *out_packet,
	size_t out_packet_capacity);

void zapret2_mac_core_shutdown(void);

#ifdef __cplusplus
}
#endif
