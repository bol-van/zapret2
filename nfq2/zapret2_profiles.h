#pragma once

#include "params.h"

#include <stdbool.h>

bool zapret2_add_desync_profile(struct desync_profile_list_head *head, unsigned int n, const char *name, struct desync_profile_list **profile);
bool zapret2_add_no_action_profile(struct desync_profile_list_head *head);
bool zapret2_apply_profile_defaults(struct desync_profile *dp);
