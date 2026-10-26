#include <stdio.h>
#include "hostlist.h"
#include "gzip.h"
#include "helpers.h"

// inplace tolower() and add to pool
static bool addpool(hostlist_pool **hostlist, char **s, const char *end, int *ct)
{
	char *p=*s;

	for (; p<end && (*p==' ' || *p=='\t') ; p++);
	*s = p;
	// comment line ?
	if (p<end && *p != '#' && *p != ';' && *p != '/' && *p != '\r' && *p != '\n')
	{
		uint32_t flags = 0;
		// entry prefixes, any order: '^' = no subdomains, '!' = negation (exception to a shorter entry)
		for (; p<end && (*p=='^' || *p=='!'); p++)
			flags |= (*p=='^') ? HOSTLIST_POOL_FLAG_STRICT_MATCH : HOSTLIST_POOL_FLAG_NEGATE;
		*s = p;
		// advance until eol lowering all chars
		for (; p<end && *p && *p!=' ' && *p!='\t' && *p!='\r' && *p != '\n'; p++) *p=tolower((unsigned char)*p);
		if (!HostlistPoolAddStrLen(hostlist, *s, p-*s, flags))
		{
			HostlistPoolDestroy(hostlist);
			*hostlist = NULL;
			return false;
		}
		if (ct) (*ct)++;
	}
	// skip remaining non-eol chars
	for (; p<end && *p && *p!='\r' && *p != '\n'; p++);
	// advance to the next line
	for (; p<end && (!*p || *p=='\r' || *p=='\n') ; p++);
	*s = p;
	return true;
}

bool AppendHostlistItem(hostlist_pool **hostlist, char *s)
{
	return addpool(hostlist,&s,s+strlen(s),NULL);
}

bool AppendHostList(hostlist_pool **hostlist, const char *filename)
{
	char *p, *e, s[4096], *zbuf;
	size_t zsize;
	int ct = 0;
	FILE *F;
	int r;

	DLOG_CONDUP("Loading hostlist %s\n",filename);

	if (!(F = fopen(filename, "rb")))
	{
		DLOG_ERR("Could not open %s\n", filename);
		return false;
	}

	if (is_gzip(F))
	{
		r = z_readfile(F,&zbuf,&zsize,0);
		fclose(F);
		if (r==Z_STREAM_END)
		{
			DLOG_CONDUP("zlib compression detected. uncompressed size : %zu\n", zsize);

			if (zbuf)
			{
				p = zbuf;
				e = zbuf + zsize;
				while(p<e)
				{
					if (!addpool(hostlist,&p,e,&ct))
					{
						DLOG_ERR("Not enough memory to store host list : %s\n", filename);
						free(zbuf);
						return false;
					}
				}
				free(zbuf);
			}
		}
		else
		{
			DLOG_ERR("zlib decompression failed : result %d\n", r);
			return false;
		}
	}
	else
	{
		DLOG_CONDUP("loading plain text list\n");

		while (fgets_safe(s, sizeof(s), F))
		{
			p = s;
			if (!addpool(hostlist,&p,p+strlen(p),&ct))
			{
				DLOG_ERR("Not enough memory to store host list : %s\n", filename);
				fclose(F);
				return false;
			}
		}
		if (ferror(F))
		{
			DLOG_PERROR("AppendHostList");
			fclose(F);
			return false;
		}
		fclose(F);
	}

	DLOG_CONDUP("Loaded %d hosts from %s\n", ct, filename);
	return true;
}

// bChanged is set to true if the list was changed and not set otherwise
static bool LoadHostList(struct hostlist_file *hfile, bool *bChanged)
{
	if (hfile->filename)
	{
		file_mod_sig fsig;
		if (!file_mod_signature(hfile->filename, &fsig))
		{
			// stat() error
			DLOG_PERROR("file_mod_signature");
			goto unchanged;
		}
		if (FILE_MOD_COMPARE(&hfile->mod_sig,&fsig)) return true; // up to date
		// check if it's readable. do not destroy in-memory copy if not
		if (!file_open_test(hfile->filename, O_RDONLY))
		{
			DLOG_PERROR("file_open_test");
			goto unchanged;
		}
		if (bChanged) *bChanged=true;
		// don't want to keep backup copy in memory - it will require *2 RAM. Problem on low-ram devices. It's better to fail hostlist read than have OOM.
		// if a file can be opened there're few chances it can't be read. fs corruption, disk error, deleted or made inaccessible between 2 syscals ?
		// it's all hypotetically possible but very unlikely. but OOM is much more real problem on an embedded device if list is large enough
		HostlistPoolDestroy(&hfile->hostlist);
		if (!AppendHostList(&hfile->hostlist, hfile->filename))
		{
			HostlistPoolDestroy(&hfile->hostlist);
			return false;
		}
		hfile->mod_sig=fsig;
	}
	return true;
unchanged:
	DLOG_ERR("cannot access hostlist file '%s'. in-memory content remains unchanged.\n",hfile->filename);
	return true;
}
static bool LoadHostLists(struct hostlist_files_head *list, bool *bChanged)
{
	bool bres=true;
	struct hostlist_file *hfile;

	LIST_FOREACH(hfile, list, next)
	{
		if (!LoadHostList(hfile, bChanged))
			// at least one failed
			bres=false;
	}
	return bres;
}

bool NonEmptyHostlist(hostlist_pool **hostlist)
{
	// add impossible hostname if the list is empty
	return *hostlist ? true : HostlistPoolAddStrLen(hostlist, "@&()", 4, 0);
}

static void MakeAutolistsNonEmpty()
{
	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		if (dpl->dp.hostlist_auto)
			NonEmptyHostlist(&dpl->dp.hostlist_auto->hostlist);
	}
}

bool LoadAllHostLists()
{
	bool bChanged=false;
	if (!LoadHostLists(&params.hostlists, &bChanged))
		return false;
	if (bChanged) MakeAutolistsNonEmpty();
	return true;
}



#define HL_NOT_FOUND    0
#define HL_FOUND        1
#define HL_NEGATED      2
// Search the host in all lists of the collection at once.
// The longest matching entry wins: go from the full host name up to the top level domain.
// A negation ('!') in any list cancels all shorter entries in all lists of the collection.
static int SearchHostLists(const struct hostlist_collection_head *hostlists, const char *kind, const char *host, bool no_match_subdomains)
{
	const char *p = host;
	const struct hostlist_item *item;
	const struct hostlist_pool *hp;
	bool bHostFull=true, bFound;

	while (p)
	{
		bFound = false;
		LIST_FOREACH(item, hostlists, next)
		{
			DLOG("[%s] %s hostlist check for %s : ", item->hfile->filename ? item->hfile->filename : "fixed", kind, p);
			hp = HostlistPoolGetStr(item->hfile->hostlist, p);
			if (!hp)
				DLOG("negative\n");
			else if ((hp->flags & HOSTLIST_POOL_FLAG_STRICT_MATCH) && !bHostFull)
				DLOG("negative : strict_mismatch : %s != %s\n", p, host);
			else if (hp->flags & HOSTLIST_POOL_FLAG_NEGATE)
			{
				DLOG("negated by !%s\n", p);
				return HL_NEGATED;
			}
			else
			{
				DLOG("positive\n");
				// Do not return yet. A negation in the next list wins
				bFound = true;
			}
		}
		if (bFound) return HL_FOUND;
		if (no_match_subdomains) break;
		p = strchr(p, '.');
		if (p) p++;
		bHostFull = false;
	}
	return HL_NOT_FOUND;
}


static bool HostlistsReloadCheck(const struct hostlist_collection_head *hostlists)
{
	struct hostlist_item *item;
	bool bChanged=false;

	LIST_FOREACH(item, hostlists, next)
	{
		if (!LoadHostList(item->hfile, &bChanged))
			return false;
	}
	// this is relatively heavy function. walks through all the profiles. do not walk if no hostlists were releaded
	if (bChanged) MakeAutolistsNonEmpty();
	return true;
}
bool HostlistsReloadCheckForProfile(const struct desync_profile *dp)
{
	return HostlistsReloadCheck(&dp->hl_collection) && HostlistsReloadCheck(&dp->hl_collection_exclude);
}
// return : true = apply fooling, false = do not apply
static bool HostlistCheck_(const struct hostlist_collection_head *hostlists, const struct hostlist_collection_head *hostlists_exclude, const char *host, bool no_match_subdomains, bool *excluded, bool bSkipReloadCheck)
{
	int r;

	if (excluded) *excluded = false;

	if (!bSkipReloadCheck)
		if (!HostlistsReloadCheck(hostlists) || !HostlistsReloadCheck(hostlists_exclude))
			return false;

	if (SearchHostLists(hostlists_exclude, "exclude", host, no_match_subdomains)==HL_FOUND)
	{
		if (excluded) *excluded = true;
		return false;
	}
	// old behavior compat: all include lists are empty means check passes
	if (!hostlist_collection_is_empty(hostlists))
	{
		r = SearchHostLists(hostlists, "include", host, no_match_subdomains);
		// negated host is treated like excluded: autohostlist must neither probe nor learn it
		if (r==HL_NEGATED && excluded) *excluded = true;
		return r==HL_FOUND;
	}
	return true;
}


// return : true = apply fooling, false = do not apply
bool HostlistCheck(const struct desync_profile *dp, const char *host, bool no_match_subdomains, bool *excluded, bool bSkipReloadCheck)
{
	DLOG("* hostlist check for profile %u (%s)\n",dp->n,PROFILE_NAME(dp));
	return HostlistCheck_(&dp->hl_collection, &dp->hl_collection_exclude, host, no_match_subdomains, excluded, bSkipReloadCheck);
}


static struct hostlist_file *RegisterHostlist_(struct hostlist_files_head *hostlists, struct hostlist_collection_head *hl_collection, const char *filename)
{
	struct hostlist_file *hfile;
	char pabs[PATH_MAX];

	if (filename)
	{
		if (!realpath(filename,pabs)) return NULL;
		if (!(hfile=hostlist_files_search(hostlists, pabs)))
			if (!(hfile=hostlist_files_add(hostlists, pabs)))
				return NULL;
		if (!hostlist_collection_search(hl_collection, pabs))
			if (!hostlist_collection_add(hl_collection, hfile))
				return NULL;
	}
	else
	{
		if (!(hfile=hostlist_files_add(hostlists, NULL)))
			return NULL;
		if (!hostlist_collection_add(hl_collection, hfile))
			return NULL;
	}

	return hfile;
}
struct hostlist_file *RegisterHostlist(struct desync_profile *dp, bool bExclude, const char *filename)
{
	if (filename && !file_size(filename,NULL))
	{
		DLOG_ERR("cannot access hostlist file '%s'\n",filename);
		return NULL;
	}
	return RegisterHostlist_(
		&params.hostlists,
		bExclude ? &dp->hl_collection_exclude : &dp->hl_collection,
		filename);
}

static void HostlistsDebugProfile(const struct desync_profile *dp, const char *entity)
{
	struct hostlist_item *hl_item;

	LIST_FOREACH(hl_item, &dp->hl_collection, next)
		if (hl_item->hfile!=dp->hostlist_auto)
		{
			if (hl_item->hfile->filename)
				DLOG("%s %u (%s) include hostlist %s%s\n",entity, dp->n, PROFILE_NAME(dp), hl_item->hfile->filename,hl_item->hfile->hostlist ? "" : " (empty)");
			else
				DLOG("%s %u (%s) include fixed hostlist%s\n",entity, dp->n, PROFILE_NAME(dp), hl_item->hfile->hostlist ? "" : " (empty)");
		}
	LIST_FOREACH(hl_item, &dp->hl_collection_exclude, next)
	{
		if (hl_item->hfile->filename)
			DLOG("%s %u (%s) exclude hostlist %s%s\n",entity, dp->n,PROFILE_NAME(dp),hl_item->hfile->filename,hl_item->hfile->hostlist ? "" : " (empty)");
		else
			DLOG("%s %u (%s) exclude fixed hostlist%s\n",entity, dp->n,PROFILE_NAME(dp),hl_item->hfile->hostlist ? "" : " (empty)");
	}
	if (dp->hostlist_auto)
		DLOG("%s %u (%s) auto hostlist %s%s\n",entity, dp->n,PROFILE_NAME(dp),dp->hostlist_auto->filename,dp->hostlist_auto->hostlist ? "" : " (empty)");
}
void HostlistsDebug()
{
	if (!params.debug) return;

	struct hostlist_file *hfile;
	struct desync_profile_list *dpl;

	LIST_FOREACH(hfile, &params.hostlists, next)
	{
		if (hfile->filename)
			DLOG("hostlist file %s%s\n",hfile->filename,hfile->hostlist ? "" : " (empty)");
		else
			DLOG("hostlist fixed%s\n",hfile->hostlist ? "" : " (empty)");
	}

	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		HostlistsDebugProfile(&dpl->dp, "profile");
	}
	LIST_FOREACH(dpl, &params.desync_templates, next)
	{
		HostlistsDebugProfile(&dpl->dp, "template");
	}
}
