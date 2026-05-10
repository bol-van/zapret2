#include "zapret2_profiles.h"

#include <stdlib.h>
#include <string.h>

bool zapret2_add_desync_profile(struct desync_profile_list_head *head, unsigned int n, const char *name, struct desync_profile_list **profile)
{
	struct desync_profile_list *entry = dp_list_add(head);
	if (!entry)
		return false;

	entry->dp.n = n;
	if (name)
	{
		entry->dp.name = strdup(name);
		if (!entry->dp.name)
			return false;
	}
	if (profile)
		*profile = entry;
	return true;
}

bool zapret2_add_no_action_profile(struct desync_profile_list_head *head)
{
	return zapret2_add_desync_profile(head, 0, "no_action", NULL);
}

bool zapret2_apply_profile_defaults(struct desync_profile *dp)
{
	// enable both ipv4 and ipv6 if not specified
	if (!dp->b_filter_l3)
		dp->filter_ipv4 = dp->filter_ipv6 = true;

	// if any filter is set - deny all unset
	if (!LIST_EMPTY(&dp->pf_tcp) || !LIST_EMPTY(&dp->pf_udp) || !LIST_EMPTY(&dp->icf) || !LIST_EMPTY(&dp->ipf))
	{
		return port_filters_deny_if_empty(&dp->pf_tcp) &&
			port_filters_deny_if_empty(&dp->pf_udp) &&
			icmp_filters_deny_if_empty(&dp->icf) &&
			ipp_filters_deny_if_empty(&dp->ipf);
	}
	return true;
}
