#pragma once

#include "params.h"

#include <stdbool.h>
#include <stddef.h>

bool zapret2_config_load_args(const char *filename, struct params_s *params, char *errbuf, size_t errbuf_len);
