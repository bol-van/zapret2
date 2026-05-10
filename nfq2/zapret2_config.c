#include "zapret2_config.h"

#include "helpers.h"

#include <stdio.h>

#if !defined(__OpenBSD__) && !defined(__ANDROID__)
#include <wordexp.h>
#endif

#define ZAPRET2_CONFIG_MAX_FILE_SIZE 16384

static void set_error(char *errbuf, size_t errbuf_len, const char *format, const char *arg)
{
	if (errbuf && errbuf_len)
		snprintf(errbuf, errbuf_len, format, arg);
}

bool zapret2_config_load_args(const char *filename, struct params_s *params, char *errbuf, size_t errbuf_len)
{
#if defined(__OpenBSD__) || defined(__ANDROID__)
	(void)filename;
	(void)params;
	set_error(errbuf, errbuf_len, "argument-file config is not supported on this platform", "");
	return false;
#else
	char buf[ZAPRET2_CONFIG_MAX_FILE_SIZE];
	size_t bufsize = sizeof(buf) - 3;

	if (!filename || !*filename)
	{
		set_error(errbuf, errbuf_len, "missing config filename%s", "");
		return false;
	}

	buf[0] = 'x';
	buf[1] = ' ';
	if (!load_file(filename, 0, buf + 2, &bufsize))
	{
		set_error(errbuf, errbuf_len, "could not load config file '%s'", filename);
		return false;
	}
	buf[bufsize + 2] = 0;

	// wordexp fails if it sees tabs or newlines between args.
	replace_char(buf, '\n', ' ');
	replace_char(buf, '\r', ' ');
	replace_char(buf, '\t', ' ');

	if (wordexp(buf, &params->wexp, WRDE_NOCMD))
	{
		set_error(errbuf, errbuf_len, "failed to split command line options from file '%s'", filename);
		return false;
	}
	return true;
#endif
}
