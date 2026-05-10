#include "zapret2_options.h"

#include "darkmagic.h"
#include "filter.h"
#include "helpers.h"
#include "hostlist.h"
#include "protocol.h"
#include "zapret2_profiles.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_error(char *errbuf, size_t errbuf_len, const char *format, const char *arg)
{
	if (errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, format, arg);
}

static bool is_hexstring(const char *filename)
{
	return filename[0] == '0' && filename[1] == 'x';
}

static bool parse_filespec(const char **filename, unsigned long long *ofs)
{
	*ofs = 0;
	if (**filename == '+')
	{
		(*filename)++;
		if (sscanf(*filename, "%llu", ofs) != 1)
			return false;
		while (**filename && **filename != '@') (*filename)++;
		if (**filename == '@') (*filename)++;
	}
	else if (**filename == '@')
		(*filename)++;
	return true;
}

static char *item_name(char **str)
{
	char *s, *p;
	size_t l;

	l = (s = strchr(*str, ':')) ? (size_t)(s - *str) : strlen(*str);
	if (!(p = malloc(l + 1)))
		return NULL;
	memcpy(p, *str, l);
	p[l] = 0;
	if (!is_identifier(p))
	{
		free(p);
		return NULL;
	}
	*str = s ? s + 1 : *str + l;
	return p;
}

static bool load_file_or_error(const char *filename, void *buf, size_t *size, char *errbuf, size_t errbuf_len)
{
	unsigned long long ofs;

	if (is_hexstring(filename))
	{
		if (!parse_hex_str(filename + 2, buf, size) || !*size)
		{
			set_error(errbuf, errbuf_len, "invalid hex string: %s", filename + 2);
			return false;
		}
		return true;
	}

	if (!parse_filespec(&filename, &ofs))
	{
		set_error(errbuf, errbuf_len, "bad file specification: %s", filename);
		return false;
	}
	if (!load_file(filename, (off_t)ofs, buf, size))
	{
		set_error(errbuf, errbuf_len, "could not read '%s'", filename);
		return false;
	}
	return true;
}

static bool load_blob_to_collection(const char *filespec, struct blob_collection_head *blobs, char *errbuf, size_t errbuf_len)
{
	struct blob_item *blob;
	uint8_t *p;
	char *name;
	char *spec;
	char *data_spec;
	size_t max_size = MAX_BLOB_SIZE;

	if (!(spec = strdup(filespec)))
	{
		set_error(errbuf, errbuf_len, "out of memory%s", "");
		return false;
	}
	data_spec = spec;
	if (!(name = item_name(&data_spec)))
	{
		free(spec);
		set_error(errbuf, errbuf_len, "bad blob specification: %s", filespec);
		return false;
	}

	if (!is_hexstring(data_spec))
	{
		const char *fn = data_spec;
		unsigned long long ofs;
		off_t fsize;

		if (!parse_filespec(&fn, &ofs) || !file_size(fn, &fsize))
		{
			free(name);
			free(spec);
			set_error(errbuf, errbuf_len, "cannot access blob file '%s'", data_spec);
			return false;
		}
		if (fsize)
		{
			if (ofs >= (unsigned long long)fsize)
			{
				free(name);
				free(spec);
				set_error(errbuf, errbuf_len, "blob offset is beyond file size: %s", data_spec);
				return false;
			}
			max_size = (size_t)(fsize - (off_t)ofs);
		}
	}

	if (blob_collection_search_name(blobs, name))
	{
		free(name);
		free(spec);
		set_error(errbuf, errbuf_len, "duplicate blob name '%s'", filespec);
		return false;
	}
	if (!(blob = blob_collection_add(blobs)) || !(blob->data = malloc(max_size + BLOB_EXTRA_BYTES)))
	{
		free(name);
		free(spec);
		set_error(errbuf, errbuf_len, "out of memory%s", "");
		return false;
	}
	blob->size = max_size;
	blob->name = name;
	if (!load_file_or_error(data_spec, blob->data, &blob->size, errbuf, errbuf_len))
	{
		free(spec);
		return false;
	}
	if (!(p = realloc(blob->data, blob->size + BLOB_EXTRA_BYTES)))
	{
		free(spec);
		set_error(errbuf, errbuf_len, "out of memory%s", "");
		return false;
	}
	blob->data = p;
	blob->size_buf = blob->size + BLOB_EXTRA_BYTES;
	free(spec);
	return true;
}

static bool parse_l7_list(char *opt, uint64_t *l7)
{
	char *e, *p, c;
	t_l7proto proto;

	for (p = opt, *l7 = 0; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}
		if ((proto = l7proto_from_name(p)) == L7_INVALID)
			return false;
		else if (proto == L7_ALL)
		{
			*l7 = 0;
			break;
		}
		else
			*l7 |= 1ULL << proto;
		if (e) *e++ = c;
		p = e;
	}
	return true;
}

static bool parse_l7p_list(char *opt, uint64_t *l7p)
{
	char *e, *p, c;
	t_l7payload payload;

	for (p = opt, *l7p = 0; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}
		if ((payload = l7payload_from_name(p)) == L7P_INVALID)
			return false;
		else if (payload == L7P_ALL)
		{
			*l7p = 0;
			break;
		}
		else
			*l7p |= 1ULL << payload;
		if (e) *e++ = c;
		p = e;
	}
	return true;
}

static bool parse_pf_list(char *opt, struct port_filters_head *pfl)
{
	char *e, *p, c;
	port_filter pf;
	bool b;

	for (p = opt; p; )
	{
		if ((e = strchr(p, ',')))
		{
			c = *e;
			*e = 0;
		}
		b = pf_parse(p, &pf) && port_filter_add(pfl, &pf);
		if (e) *e++ = c;
		if (!b) return false;
		p = e;
	}
	return true;
}

static bool lua_call_param_add(char *opt, struct str2_list_head *args)
{
	char c, *p;
	struct str2_list *arg;

	if ((p = strchr(opt, '=')))
	{
		c = *p;
		*p = 0;
	}
	if (!is_identifier(opt) || !(arg = str2list_add(args)))
	{
		if (p) *p = c;
		return false;
	}
	arg->str1 = strdup(opt);
	if (p)
	{
		arg->str2 = strdup(p + 1);
		*p = c;
		if (!arg->str2) return false;
	}
	return arg->str1;
}

static struct func_list *parse_lua_call(char *opt, struct func_list_head *flist)
{
	char *name, *e, *p, c;
	bool b, last;
	struct func_list *f = NULL;

	if (!(name = item_name(&opt)))
		return NULL;
	if (!is_identifier(name) || !(f = funclist_add_tail(flist, name)))
		goto err;
	for (p = opt; p && *p; )
	{
		for (e = p; *e && *e != ':'; e++)
		{
			if (e[0] == '\\' && e[1] == ':')
				memmove(e, e + 1, strlen(e));
		}
		last = !*e;
		c = *e;
		*e = 0;
		b = lua_call_param_add(p, &f->args);
		if (!last) *e++ = c;
		if (!b) goto err;
		p = e;
	}
	free(name);
	return f;
err:
	free(name);
	return NULL;
}

static bool add_lua_init_script(struct params_s *params, const char *opt, char *errbuf, size_t errbuf_len)
{
	char pabs[PATH_MAX + 1], *p;

	if (*opt == '@')
	{
		if (!realpath_any(opt + 1, pabs + 1))
		{
			set_error(errbuf, errbuf_len, "bad lua init file '%s'", opt + 1);
			return false;
		}
		*(p = pabs) = '@';
	}
	else
		p = (char *)opt;
	if (!strlist_add_tail(&params->lua_init_scripts, p))
	{
		set_error(errbuf, errbuf_len, "out of memory%s", "");
		return false;
	}
	return true;
}

static bool split_option(char *arg, char **name, char **value)
{
	char *eq;

	if (strncmp(arg, "--", 2))
		return false;
	*name = arg + 2;
	if ((eq = strchr(*name, '=')))
	{
		*eq = 0;
		*value = eq + 1;
	}
	else
		*value = NULL;
	return true;
}

bool zapret2_engine_apply_args(
	struct params_s *params,
	int argc,
	char **argv,
	unsigned int *desync_profile_count,
	char *errbuf,
	size_t errbuf_len)
{
	struct desync_profile_list *dpl = LIST_FIRST(&params->desync_profiles);
	struct desync_profile *dp = dpl ? &dpl->dp : NULL;
	uint64_t payload_type = 0;
	struct packet_range range_in = PACKET_RANGE_NEVER, range_out = PACKET_RANGE_ALWAYS;

	if (!dp)
	{
		set_error(errbuf, errbuf_len, "missing initial desync profile%s", "");
		return false;
	}

	for (int i = 1; i < argc; i++)
	{
		char *name, *value;
		if (!split_option(argv[i], &name, &value))
		{
			set_error(errbuf, errbuf_len, "unsupported positional argument '%s'", argv[i]);
			return false;
		}

		if (!value && strcmp(name, "new"))
		{
			if (i + 1 >= argc)
			{
				set_error(errbuf, errbuf_len, "missing value for --%s", name);
				return false;
			}
			value = argv[++i];
		}

		if (!strcmp(name, "intercept"))
			params->intercept = !value || atoi(value);
		else if (!strcmp(name, "lua-init"))
		{
			if (!add_lua_init_script(params, value, errbuf, errbuf_len))
				return false;
		}
		else if (!strcmp(name, "blob"))
		{
			if (!load_blob_to_collection(value, &params->blobs, errbuf, errbuf_len))
				return false;
		}
		else if (!strcmp(name, "hostlist"))
		{
			if (!RegisterHostlist(dp, false, value))
			{
				set_error(errbuf, errbuf_len, "failed to register hostlist '%s'", value);
				return false;
			}
		}
		else if (!strcmp(name, "filter-tcp"))
		{
			if (!parse_pf_list(value, &dp->pf_tcp))
			{
				set_error(errbuf, errbuf_len, "invalid tcp port filter '%s'", value);
				return false;
			}
		}
		else if (!strcmp(name, "filter-udp"))
		{
			if (!parse_pf_list(value, &dp->pf_udp))
			{
				set_error(errbuf, errbuf_len, "invalid udp port filter '%s'", value);
				return false;
			}
		}
		else if (!strcmp(name, "filter-l7"))
		{
			if (!parse_l7_list(value, &dp->filter_l7))
			{
				set_error(errbuf, errbuf_len, "invalid l7 filter '%s'", value);
				return false;
			}
			dp->b_filter_l7 = true;
		}
		else if (!strcmp(name, "payload"))
		{
			if (!parse_l7p_list(value, &payload_type))
			{
				set_error(errbuf, errbuf_len, "invalid payload filter '%s'", value);
				return false;
			}
		}
		else if (!strcmp(name, "lua-desync"))
		{
			struct func_list *f;
			if (!(f = parse_lua_call(value, &dp->lua_desync)))
			{
				set_error(errbuf, errbuf_len, "invalid lua function call '%s'", value);
				return false;
			}
			f->payload_type = payload_type;
			f->range_in = range_in;
			f->range_out = range_out;
		}
		else if (!strcmp(name, "new"))
		{
			if (!zapret2_add_desync_profile(&params->desync_profiles, ++(*desync_profile_count), value, &dpl))
			{
				set_error(errbuf, errbuf_len, "could not create new desync profile%s", "");
				return false;
			}
			dp = &dpl->dp;
			payload_type = 0;
			range_in = PACKET_RANGE_NEVER;
			range_out = PACKET_RANGE_ALWAYS;
		}
		else
		{
			set_error(errbuf, errbuf_len, "unsupported engine preset option '--%s'", name);
			return false;
		}
	}
	return true;
}
