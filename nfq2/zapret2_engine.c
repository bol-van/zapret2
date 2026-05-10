#include "zapret2_engine.h"

#include "darkmagic.h"
#include "desync.h"
#include "hostlist.h"
#include "ipset.h"
#include "lua.h"
#include "params.h"
#include "zapret2_config.h"
#include "zapret2_defaults.h"
#include "zapret2_options.h"
#include "zapret2_profiles.h"

#include <stdio.h>
#include <string.h>

static int engine_ready;
extern struct params_s params;

enum zapret2_engine_init_status zapret2_engine_init_from_config(
	const char *config_file,
	char *errbuf,
	size_t errbuf_len)
{
	int arg_count = 0;
	unsigned int desync_profile_count = 1;
	struct desync_profile_list *dpl;

	zapret2_engine_shutdown();
	init_params(&params);
	if (config_file && *config_file && !zapret2_config_load_args(config_file, &params, errbuf, errbuf_len))
	{
		zapret2_engine_shutdown();
		return ZAPRET2_ENGINE_INIT_ERROR;
	}
	if (!zapret2_apply_default_blobs(&params.blobs))
	{
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "could not apply zapret2 default blobs");
		zapret2_engine_shutdown();
		return ZAPRET2_ENGINE_INIT_ERROR;
	}
	if (!zapret2_add_desync_profile(&params.desync_profiles, desync_profile_count, NULL, NULL))
	{
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "could not create initial zapret2 desync profile");
		zapret2_engine_shutdown();
		return ZAPRET2_ENGINE_INIT_ERROR;
	}
	if (config_file && *config_file)
	{
		arg_count = (int)params.wexp.we_wordc - 1;
		if (!zapret2_engine_apply_args(&params, (int)params.wexp.we_wordc, params.wexp.we_wordv, &desync_profile_count, errbuf, errbuf_len))
		{
			zapret2_engine_shutdown();
			return ZAPRET2_ENGINE_INIT_ERROR;
		}
	}
	if (!zapret2_add_no_action_profile(&params.desync_profiles))
	{
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "could not create default no_action profile");
		zapret2_engine_shutdown();
		return ZAPRET2_ENGINE_INIT_ERROR;
	}
	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		if (!zapret2_apply_profile_defaults(&dpl->dp))
		{
			if (errbuf && errbuf_len)
				snprintf(errbuf, errbuf_len, "could not apply profile defaults");
			zapret2_engine_shutdown();
			return ZAPRET2_ENGINE_INIT_ERROR;
		}
	}
	dp_list_destroy(&params.desync_templates);
	if (!LoadAllHostLists())
	{
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "hostlists load failed");
		zapret2_engine_shutdown();
		return ZAPRET2_ENGINE_INIT_ERROR;
	}
	if (!LoadAllIpsets())
	{
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "ipsets load failed");
		zapret2_engine_shutdown();
		return ZAPRET2_ENGINE_INIT_ERROR;
	}
	if (!lua_test_init_script_files())
	{
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "lua init script validation failed");
		zapret2_engine_shutdown();
		return ZAPRET2_ENGINE_INIT_ERROR;
	}
	if (!lua_init())
	{
		if (errbuf && errbuf_len)
			snprintf(errbuf, errbuf_len, "lua initialization failed");
		zapret2_engine_shutdown();
		return ZAPRET2_ENGINE_INIT_ERROR;
	}
	if (!params.ctrack_disable)
		ConntrackPoolInit(&params.conntrack, 10, params.ctrack_t_syn, params.ctrack_t_est, params.ctrack_t_fin, params.ctrack_t_udp);

	engine_ready = 1;
	if (errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, "initialized %u user profile(s) from %d config arguments", desync_profile_count, arg_count);
	return ZAPRET2_ENGINE_INIT_OK;
}

int zapret2_engine_is_ready(void)
{
	return engine_ready;
}

void zapret2_engine_shutdown(void)
{
	cleanup_params(&params);
	engine_ready = 0;
}

struct zapret2_engine_packet_result zapret2_engine_process_packet(
	uint32_t fwmark,
	const char *ifin,
	const char *ifout,
	const uint8_t *packet,
	size_t packet_len,
	uint8_t *out_packet,
	size_t out_packet_capacity)
{
	struct zapret2_engine_packet_result result = {
		.verdict = ZAPRET2_ENGINE_ERROR,
		.packet_len = 0
	};
	size_t mod_len = out_packet_capacity;
	uint8_t verdict;

	if (!engine_ready)
		return result;

	if (!packet || !packet_len || !out_packet || !out_packet_capacity)
		return result;

	verdict = dpi_desync_packet(fwmark, ifin, ifout, packet, packet_len, out_packet, &mod_len);
	switch (verdict & VERDICT_MASK) {
	case VERDICT_PASS:
		if (out_packet_capacity < packet_len)
			return result;
		memcpy(out_packet, packet, packet_len);
		result.verdict = ZAPRET2_ENGINE_PASS;
		result.packet_len = packet_len;
		return result;
	case VERDICT_MODIFY:
		result.verdict = ZAPRET2_ENGINE_MODIFY;
		result.packet_len = mod_len;
		return result;
	case VERDICT_DROP:
		result.verdict = ZAPRET2_ENGINE_DROP;
		result.packet_len = 0;
		return result;
	default:
		return result;
	}
}
