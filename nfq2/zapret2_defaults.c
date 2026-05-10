#include "zapret2_defaults.h"

#include "params.h"

#include <stdlib.h>
#include <string.h>

static bool add_named_blob(struct blob_collection_head *blobs, const char *name, const void *data, size_t size, size_t size_reserve)
{
	struct blob_item *blob;

	if (blob_collection_search_name(blobs, name))
		return false;

	blob = blob_collection_add_blob(blobs, data, size, size_reserve);
	if (!blob)
		return false;

	blob->name = strdup(name);
	if (!blob->name)
		return false;
	return true;
}

bool zapret2_apply_default_blobs(struct blob_collection_head *blobs)
{
	uint8_t quic[620];

	if (!add_named_blob(blobs, "fake_default_tls", fake_tls_clienthello_default, sizeof(fake_tls_clienthello_default), BLOB_EXTRA_BYTES))
		return false;
	if (!add_named_blob(blobs, "fake_default_http", fake_http_request_default, strlen(fake_http_request_default), 0))
		return false;

	memset(quic, 0, sizeof(quic));
	quic[0] = 0x40;
	return add_named_blob(blobs, "fake_default_quic", quic, sizeof(quic), 0);
}
