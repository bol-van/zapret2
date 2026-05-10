#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum zapret2_engine_verdict {
	ZAPRET2_ENGINE_PASS = 0,
	ZAPRET2_ENGINE_MODIFY = 1,
	ZAPRET2_ENGINE_DROP = 2,
	ZAPRET2_ENGINE_ERROR = 255
};

struct zapret2_engine_packet_result {
	enum zapret2_engine_verdict verdict;
	size_t packet_len;
};

enum zapret2_engine_init_status {
	ZAPRET2_ENGINE_INIT_OK = 0,
	ZAPRET2_ENGINE_INIT_NOT_IMPLEMENTED = 1,
	ZAPRET2_ENGINE_INIT_ERROR = 255
};

/*
 * Initialize reusable zapret2 core state for OS backends that do not own a
 * Linux/BSD/Windows packet loop.
 *
 * The intended config format is the same argument-file format accepted by
 * nfqws2/dvtws2/winws2. Full option parsing still has to be extracted from
 * nfqws.c; until then this function reports NOT_IMPLEMENTED.
 */
enum zapret2_engine_init_status zapret2_engine_init_from_config(
	const char *config_file,
	char *errbuf,
	size_t errbuf_len);

int zapret2_engine_is_ready(void);
void zapret2_engine_shutdown(void);

/*
 * Packet-processing API shared by OS backends.
 *
 * Existing nfqws2/dvtws2/winws2 loops own packet capture and reinjection.
 * Native macOS needs the same split: Network Extension owns packet capture,
 * this engine owns zapret2 protocol parsing and Lua desync decisions.
 */
struct zapret2_engine_packet_result zapret2_engine_process_packet(
	uint32_t fwmark,
	const char *ifin,
	const char *ifout,
	const uint8_t *packet,
	size_t packet_len,
	uint8_t *out_packet,
	size_t out_packet_capacity);

#ifdef __cplusplus
}
#endif
