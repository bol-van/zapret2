#include "Zapret2CoreBridge.h"

#include "../../../nfq2/zapret2_engine.h"

/*
 * This file is the native macOS seam into the zapret2 packet engine.
 *
 * It is built as a small bridge archive. The Network Extension adapter owns
 * packet capture and relay; this bridge owns initialization and calls into the
 * reusable zapret2_engine API.
 */

int zapret2_mac_core_init(const char *config_file, char *errbuf, size_t errbuf_len)
{
	enum zapret2_engine_init_status status =
		zapret2_engine_init_from_config(config_file, errbuf, errbuf_len);
	return status == ZAPRET2_ENGINE_INIT_OK ? 0 : -1;
}

struct zapret2_mac_packet_result zapret2_mac_core_process_packet(
	const uint8_t *packet,
	size_t packet_len,
	const char *ifin,
	const char *ifout,
	uint8_t *out_packet,
	size_t out_packet_capacity)
{
	struct zapret2_mac_packet_result result = {
		.verdict = ZAPRET2_MAC_ERROR,
		.packet_len = 0
	};
	struct zapret2_engine_packet_result engine_result =
		zapret2_engine_process_packet(0, ifin, ifout, packet, packet_len, out_packet, out_packet_capacity);

	switch (engine_result.verdict) {
	case ZAPRET2_ENGINE_PASS:
		result.verdict = ZAPRET2_MAC_PASS;
		result.packet_len = engine_result.packet_len;
		return result;
	case ZAPRET2_ENGINE_MODIFY:
		result.verdict = ZAPRET2_MAC_MODIFY;
		result.packet_len = engine_result.packet_len;
		return result;
	case ZAPRET2_ENGINE_DROP:
		result.verdict = ZAPRET2_MAC_DROP;
		result.packet_len = 0;
		return result;
	default:
		result.verdict = ZAPRET2_MAC_ERROR;
		result.packet_len = 0;
		return result;
	}
}

void zapret2_mac_core_shutdown(void)
{
	zapret2_engine_shutdown();
}
