#pragma once

#include "params.h"

#include <stdbool.h>
#include <stddef.h>

bool zapret2_engine_apply_args(
	struct params_s *params,
	int argc,
	char **argv,
	unsigned int *desync_profile_count,
	char *errbuf,
	size_t errbuf_len);
