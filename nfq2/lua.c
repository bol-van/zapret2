#include <time.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net/if.h>
#include <errno.h>
#include <sys/ioctl.h>

#ifdef __ANDROID__
#include "andr/ifaddrs.h"
#else
#include <ifaddrs.h>
#endif

#ifdef __FreeBSD__

#include <sys/thr.h>

#elif defined(__linux__)

#include <sys/syscall.h>

#elif defined(__CYGWIN__)

#include <processthreadsapi.h>

// header hell conflicts between unix and win32
typedef struct in6_addr IN6_ADDR, *PIN6_ADDR, *LPIN6_ADDR;
typedef struct sockaddr	*LPSOCKADDR;
typedef struct _SOCKET_ADDRESS {
  LPSOCKADDR lpSockaddr;
  int iSockaddrLength;
} SOCKET_ADDRESS,*PSOCKET_ADDRESS,*LPSOCKET_ADDRESS;
#define _WINSOCK2API_
#define _NETIOAPI_H_
#include <iphlpapi.h>

#elif defined(__APPLE__)

#include <pthread.h>

#endif

#include "lua.h"
#include "params.h"
#include "gzip.h"
#include "helpers.h"
#include "nfqws.h"
#include "conntrack.h"
#include "crypto/sha.h"
#include "crypto/aes-gcm.h"
#include "crypto/aes-ctr.h"


void desync_instance(const char *func, unsigned int dp_n, unsigned int func_n, char *instance, size_t inst_size)
{
	snprintf(instance, inst_size, "%s_%u_%u", func, dp_n, func_n);
}

static void lua_check_argc(lua_State *L, const char *where, int argc)
{
	int num_args = lua_gettop(L);
	if (num_args != argc)
		luaL_error(L, "%s expect exactly %d arguments, got %d", where, argc, num_args);
}
static void lua_check_argc_range(lua_State *L, const char *where, int argc_min, int argc_max)
{
	int num_args = lua_gettop(L);
	if (num_args < argc_min || num_args > argc_max)
		luaL_error(L, "%s expect from %d to %d arguments, got %d", where, argc_min, argc_max, num_args);
}


#if LUA_VERSION_NUM < 502
int lua_absindex(lua_State *L, int idx)
{
	// convert relative index to absolute
	return idx<0 ? lua_gettop(L) + idx + 1 : idx;
}
#endif

static int luacall_DLOG(lua_State *L)
{
	lua_check_argc(L,"DLOG",1);
	DLOG("LUA: %s\n",luaL_checkstring(L,1));
	return 0;
}
static int luacall_DLOG_ERR(lua_State *L)
{
	lua_check_argc(L,"DLOG_ERR",1);
	DLOG_ERR("LUA: %s\n",luaL_checkstring(L,1));
	return 0;
}
static int luacall_DLOG_CONDUP(lua_State *L)
{
	lua_check_argc(L,"DLOG_CONDUP",1);
	DLOG_CONDUP("LUA: %s\n",luaL_checkstring(L,1));
	return 0;
}

const char *lua_reqlstring(lua_State *L,int idx,size_t *len)
{
	luaL_checktype(L,idx,LUA_TSTRING);
	return lua_tolstring(L,idx,len);
}
const char *lua_reqstring(lua_State *L,int idx)
{
	luaL_checktype(L,idx,LUA_TSTRING);
	return lua_tostring(L,idx);
}


static int luacall_bitlshift(lua_State *L)
{
	lua_check_argc(L,"bitlshift",2);
	int64_t v=(int64_t)luaL_checklint(L,1);
	lua_Integer shift = luaL_checkinteger(L,2);
	if (shift>48 || shift<0 || v>0xFFFFFFFFFFFF || v<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
	uint64_t u = v & 0xFFFFFFFFFFFF;
	lua_pushlint(L,(u << shift) & 0xFFFFFFFFFFFF);
	return 1;
}
static int luacall_bitrshift(lua_State *L)
{
	lua_check_argc(L,"bitrshift",2);
	int64_t v=(int64_t)luaL_checklint(L,1);
	lua_Integer shift = luaL_checkinteger(L,2);
	if (shift>48 || shift<0 || v>0xFFFFFFFFFFFF || v<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
	uint64_t u = v & 0xFFFFFFFFFFFF;
	lua_pushlint(L,u >> shift);
	return 1;
}
static int luacall_bitand(lua_State *L)
{
	lua_check_argc_range(L,"bitand",2,100);
	int argc = lua_gettop(L);
	int64_t v;
	uint64_t sum=0xFFFFFFFFFFFF;
	for(int i=1;i<=argc;i++)
	{
		v=(int64_t)luaL_checklint(L,i);
		if (v>0xFFFFFFFFFFFF || v<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
		sum &= (uint64_t)v;
	}
	lua_pushlint(L,sum);
	return 1;
}
static int luacall_bitor(lua_State *L)
{
	lua_check_argc_range(L,"bitor",1,100);
	int argc = lua_gettop(L);
	int64_t v;
	uint64_t sum=0;
	for(int i=1;i<=argc;i++)
	{
		v=(int64_t)luaL_checklint(L,i);
		if (v>0xFFFFFFFFFFFF || v<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
		sum |= (uint64_t)(v & 0xFFFFFFFFFFFF);
	}
	lua_pushlint(L,sum);
	return 1;
}
static int luacall_bitxor(lua_State *L)
{
	lua_check_argc_range(L,"bitxor",1,100);
	int argc = lua_gettop(L);
	int64_t v;
	uint64_t sum=0;
	for(int i=1;i<=argc;i++)
	{
		v=(int64_t)luaL_checklint(L,i);
		if (v>0xFFFFFFFFFFFF || v<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
		sum ^= (uint64_t)(v & 0xFFFFFFFFFFFF);
	}
	lua_pushlint(L,sum);
	return 1;
}
static int lua_bitnotx(lua_State *L, int64_t max)
{
	lua_check_argc(L,"bitnot",1);
	int64_t v=(int64_t)luaL_checklint(L,1);
	if (v>max || v<-max) luaL_error(L, "out of range");
	lua_pushlint(L,~(uint64_t)v & max);
	return 1;
}
static int luacall_bitnot8(lua_State *L)
{
	lua_check_argc(L,"bitnot8",1);
	return lua_bitnotx(L, 0xFF);
}
static int luacall_bitnot16(lua_State *L)
{
	lua_check_argc(L,"bitnot16",1);
	return lua_bitnotx(L, 0xFFFF);
}
static int luacall_bitnot24(lua_State *L)
{
	lua_check_argc(L,"bitnot24",1);
	return lua_bitnotx(L, 0xFFFFFF);
}
static int luacall_bitnot32(lua_State *L)
{
	lua_check_argc(L,"bitnot32",1);
	return lua_bitnotx(L, 0xFFFFFFFF);
}
static int luacall_bitnot48(lua_State *L)
{
	lua_check_argc(L,"bitnot48",1);
	return lua_bitnotx(L, 0xFFFFFFFFFFFF);
}
static int luacall_bitget(lua_State *L)
{
	lua_check_argc(L,"bitget",3);

	int64_t iwhat = (int64_t)luaL_checklint(L,1);
	if (iwhat>0xFFFFFFFFFFFF || iwhat<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
	uint64_t what = (uint64_t)iwhat;
	lua_Integer from = luaL_checkinteger(L,2);
	lua_Integer to = luaL_checkinteger(L,3);
	if (from<0 || to<0 || from>to || from>47 || to>47)
		luaL_error(L, "bit range invalid");

	what = (what >> from) & ~((uint64_t)-1 << (to-from+1));

	lua_pushlint(L,what);
	return 1;
}
static int luacall_bitset(lua_State *L)
{
	lua_check_argc(L,"bitset",4);

	int64_t iwhat = (int64_t)luaL_checklint(L,1);
	if (iwhat>0xFFFFFFFFFFFF || iwhat<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
	uint64_t what = (uint64_t)iwhat;
	lua_Integer from = luaL_checkinteger(L,2);
	lua_Integer to = luaL_checkinteger(L,3);
	int64_t iset = (int64_t)luaL_checklint(L,4);
	if (iset>0xFFFFFFFFFFFF || iset<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
	uint64_t set = (uint64_t)iset;
	if (from<0 || to<0 || from>to || from>47 || to>47)
		luaL_error(L, "bit range invalid");

	uint64_t mask = ~((uint64_t)-1 << (to-from+1));
	set = (set & mask) << from;
	mask <<= from;
	what = what & ~mask | set;

	lua_pushlint(L,what);
	return 1;
}

static int luacall_u8(lua_State *L)
{
	lua_check_argc_range(L,"u8",1,2);

	int argc=lua_gettop(L);
	size_t l;
	lua_Integer offset;
	const uint8_t *p = (uint8_t*)lua_reqlstring(L,1,&l);
	offset = (argc>=2 && lua_type(L,2)!=LUA_TNIL) ? luaL_checkinteger(L,2)-1 : 0;
	if (offset<0 || (offset+1)>l) luaL_error(L, "out of range");

	lua_pushinteger(L,p[offset]);
	return 1;
}
static int luacall_u16(lua_State *L)
{
	lua_check_argc_range(L,"u16",1,2);

	int argc=lua_gettop(L);
	size_t l;
	lua_Integer offset;
	const uint8_t *p = (uint8_t*)lua_reqlstring(L,1,&l);
	offset = (argc>=2 && lua_type(L,2)!=LUA_TNIL) ? luaL_checkinteger(L,2)-1 : 0;
	if (offset<0 || (offset+2)>l) luaL_error(L, "out of range");

	lua_pushinteger(L,pntoh16(p+offset));
	return 1;
}
static int luacall_u24(lua_State *L)
{
	lua_check_argc_range(L,"u24",1,2);

	int argc=lua_gettop(L);
	size_t l;
	lua_Integer offset;
	const uint8_t *p = (uint8_t*)lua_reqlstring(L,1,&l);
	offset = (argc>=2 && lua_type(L,2)!=LUA_TNIL) ? luaL_checkinteger(L,2)-1 : 0;
	if (offset<0 || (offset+3)>l) luaL_error(L, "out of range");

	lua_pushinteger(L,pntoh24(p+offset));
	return 1;
}
static int luacall_u32(lua_State *L)
{
	lua_check_argc_range(L,"u32",1,2);

	int argc=lua_gettop(L);
	size_t l;
	lua_Integer offset;
	const uint8_t *p = (uint8_t*)lua_reqlstring(L,1,&l);
	offset = (argc>=2 && lua_type(L,2)!=LUA_TNIL) ? luaL_checkinteger(L,2)-1 : 0;
	if (offset<0 || (offset+4)>l) luaL_error(L, "out of range");

	lua_pushlint(L,pntoh32(p+offset));
	return 1;
}
static int luacall_u48(lua_State *L)
{
	lua_check_argc_range(L,"u48",1,2);

	int argc=lua_gettop(L);
	size_t l;
	lua_Integer offset;
	const uint8_t *p = (uint8_t*)lua_reqlstring(L,1,&l);
	offset = (argc>=2 && lua_type(L,2)!=LUA_TNIL) ? luaL_checkinteger(L,2)-1 : 0;
	if (offset<0 || (offset+6)>l) luaL_error(L, "out of range");

	lua_pushlint(L,pntoh48(p+offset));
	return 1;
}
static int luacall_swap16(lua_State *L)
{
	lua_check_argc(L,"swap16",1);

	int64_t i = (int64_t)luaL_checklint(L,1);
	if (i>0xFFFF || i<-(int64_t)0xFFFF) luaL_error(L, "out of range");
	uint16_t u = (uint16_t)i;
	lua_pushinteger(L,bswap16(u));
	return 1;
}
static int luacall_swap24(lua_State *L)
{
	lua_check_argc(L,"swap24",1);

	int64_t i =(int64_t)luaL_checklint(L,1);
	if (i>0xFFFFFF || i<-(int64_t)0xFFFFFF) luaL_error(L, "out of range");
	uint32_t u = (uint32_t)i;
	lua_pushlint(L,bswap24(u));
	return 1;
}
static int luacall_swap32(lua_State *L)
{
	lua_check_argc(L,"swap32",1);

	int64_t i =(int64_t)luaL_checklint(L,1);
	if (i>0xFFFFFFFF || i<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
	uint32_t u = (uint32_t)i;
	lua_pushlint(L,__builtin_bswap32(u));
	return 1;
}
static int luacall_swap48(lua_State *L)
{
	lua_check_argc(L,"swap48",1);

	int64_t i =(int64_t)luaL_checklint(L,1);
	if (i>0xFFFFFFFFFFFF || i<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
	uint64_t u = (uint64_t)i;
	lua_pushlint(L, bswap48(u));
	return 1;
}
static int lua_uxadd(lua_State *L, int64_t max)
{
	int64_t v;
	uint64_t sum=0;
	int argc = lua_gettop(L);
	for(int i=1;i<=argc;i++)
	{
		v = (int64_t)luaL_checklint(L,i);
		if (v>max || v<-max) luaL_error(L, "out of range");
		sum+=(uint64_t)v;
	}
	lua_pushlint(L, sum & max);
	return 1;
}
static int luacall_u8add(lua_State *L)
{
	lua_check_argc_range(L,"u8add",1,100);
	return lua_uxadd(L, 0xFF);
}
static int luacall_u16add(lua_State *L)
{
	lua_check_argc_range(L,"u16add",1,100);
	return lua_uxadd(L, 0xFFFF);
}
static int luacall_u24add(lua_State *L)
{
	lua_check_argc_range(L,"u24add",1,100);
	return lua_uxadd(L, 0xFFFFFF);
}
static int luacall_u32add(lua_State *L)
{
	lua_check_argc_range(L,"u32add",1,100);
	return lua_uxadd(L, 0xFFFFFFFF);
}
static int luacall_u48add(lua_State *L)
{
	lua_check_argc_range(L,"u48add",1,100);
	return lua_uxadd(L, 0xFFFFFFFFFFFF);
}

static int luacall_bu8(lua_State *L)
{
	lua_check_argc(L,"bu8",1);

	int64_t i = (int64_t)luaL_checklint(L,1);
	if (i>0xFF || i<-(lua_Integer)0xFF) luaL_error(L, "out of range");
	uint8_t v=(uint8_t)i;
	lua_pushlstring(L,(char*)&v,1);
	return 1;
}
static int luacall_bu16(lua_State *L)
{
	lua_check_argc(L,"bu16",1);

	int64_t i = (int64_t)luaL_checklint(L,1);
	if (i>0xFFFF || i<-(lua_Integer)0xFFFF) luaL_error(L, "out of range");
	uint8_t v[2];
	phton16(v,(uint16_t)i);
	lua_pushlstring(L,(char*)v,2);
	return 1;
}
static int luacall_bu24(lua_State *L)
{
	lua_check_argc(L,"bu24",1);

	int64_t i = (int64_t)luaL_checklint(L,1);
	if (i>0xFFFFFF || i<-(lua_Integer)0xFFFFFF) luaL_error(L, "out of range");
	uint8_t v[3];
	phton24(v,(uint32_t)i);
	lua_pushlstring(L,(char*)v,3);
	return 1;
}
static int luacall_bu32(lua_State *L)
{
	lua_check_argc(L,"bu32",1);

	int64_t i = (int64_t)luaL_checklint(L,1);
	if (i>0xFFFFFFFF || i<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
	uint8_t v[4];
	phton32(v,(uint32_t)i);
	lua_pushlstring(L,(char*)v,4);
	return 1;
}
static int luacall_bu48(lua_State *L)
{
	lua_check_argc(L,"bu48",1);

	int64_t i = (int64_t)luaL_checklint(L,1);
	if (i>0xFFFFFFFFFFFF || i<-(int64_t)0xFFFFFFFFFFFF) luaL_error(L, "out of range");
	uint8_t v[6];
	phton48(v,(uint64_t)i);
	lua_pushlstring(L,(char*)v,6);
	return 1;
}

static int luacall_divint(lua_State *L)
{
	lua_check_argc(L,"divint",2);
	int64_t v1=(int64_t)luaL_checklint(L,1);
	int64_t v2=(int64_t)luaL_checklint(L,2);
	if (v2)
		lua_pushlint(L,v1/v2);
	else
		lua_pushnil(L);
	return 1;
}

static int luacall_brandom(lua_State *L)
{
	lua_check_argc(L,"brandom",1);

	LUA_STACK_GUARD_ENTER(L)
	lua_Integer len = luaL_checkinteger(L,1);
	if (len<0) luaL_error(L, "brandom: invalid arg");
	uint8_t *p = lua_newuserdata(L, len);
	fill_random_bytes(p,len);
	lua_pushlstring(L,(char*)p,len);
	lua_remove(L,-2);
	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_brandom_az(lua_State *L)
{
	lua_check_argc(L,"brandom_az",1);

	LUA_STACK_GUARD_ENTER(L)
	lua_Integer len = luaL_checkinteger(L,1);
	if (len<0) luaL_error(L, "brandom: invalid arg");
	uint8_t *p = lua_newuserdata(L, len);
	fill_random_az(p,len);
	lua_pushlstring(L,(char*)p,len);
	lua_remove(L,-2);
	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_brandom_az09(lua_State *L)
{
	lua_check_argc(L,"brandom_az09",1);

	LUA_STACK_GUARD_ENTER(L)
	lua_Integer len = luaL_checkinteger(L,1);
	if (len<0) luaL_error(L, "brandom: invalid arg");
	uint8_t *p = lua_newuserdata(L, len);
	fill_random_az09(p,len);
	lua_pushlstring(L,(char*)p,len);
	lua_remove(L,-2);
	LUA_STACK_GUARD_RETURN(L,1)
}

// hacky function. breaks immutable string behavior.
// if you change a string, it will change in all variables that hold the same string
/*
static int luacall_memcpy(lua_State *L)
{
	// memcpy(to,to_offset,from,from_offset,size)
	lua_check_argc_range(L,"memcpy",3,5);

	size_t lfrom,lto;
	lua_Integer off_from,off_to,size;
	int argc=lua_gettop(L);
	const uint8_t *from = (uint8_t*)luaL_checklstring(L,3,&lfrom);
	uint8_t *to = (uint8_t*)luaL_checklstring(L,1,&lto);
	off_from = argc>=4 ? luaL_checkinteger(L,4)-1 : 0;
	off_to = luaL_checkinteger(L,2)-1;
	if (off_from<0 || off_to<0 || off_from>lfrom || off_to>lto)
		luaL_error(L, "out of range");
	size = argc>=5 ? luaL_checkinteger(L,5) : lfrom-off_from;
	if (size<0 || (off_from+size)>lfrom || (off_to+size)>lto)
		luaL_error(L, "out of range");
	memcpy(to+off_to,from+off_from,size);
	return 0;
}
*/

static int luacall_parse_hex(lua_State *L)
{
	lua_check_argc(L,"parse_hex",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t l;
	const char *hex = lua_reqlstring(L,1,&l);
	if ((l&1)) goto err;
	l>>=1;
	uint8_t *p = lua_newuserdata(L, l);
	if (!parse_hex_str(hex,p,&l))
	{
		lua_pop(L,1);
		goto err;
	}
	lua_pushlstring(L,(char*)p,l);
	lua_remove(L,-2);
ex:
	LUA_STACK_GUARD_RETURN(L,1)
err:
	lua_pushnil(L);
	goto ex;
}



static SHAversion lua_hash_type(lua_State *L, const char *s_hash_type)
{
	SHAversion sha_ver;
	if (!strcmp(s_hash_type,"sha256"))
		sha_ver = SHA256;
	else if (!strcmp(s_hash_type,"sha224"))
		sha_ver = SHA224;
	else
		luaL_error(L, "unsupported hash type %s", s_hash_type);
	return sha_ver;
}

static int luacall_bcryptorandom(lua_State *L)
{
	lua_check_argc(L,"bcryptorandom",1);

	LUA_STACK_GUARD_ENTER(L)

	lua_Integer len = luaL_checkinteger(L,1);
	if (len<0) luaL_error(L, "bcryptorandom: invalid arg");

	uint8_t *p = lua_newuserdata(L, len);
	if (!fill_crypto_random_bytes(p,len))
	{
		// this is fatal. they expect us to give them crypto secure random blob
		luaL_error(L, "could not get entropy bytes");
	}

	lua_pushlstring(L,(char*)p,len);
	lua_remove(L,-2);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luac_bop(lua_State *L, const char *name, void (*op)(const uint8_t *x1, const uint8_t *x2, uint8_t *result, size_t sz))
{
	lua_check_argc(L,name,2);

	LUA_STACK_GUARD_ENTER(L)

	size_t sz1,sz2;
	const uint8_t *d1 = (const uint8_t*)lua_reqlstring(L,1,&sz1);
	const uint8_t *d2 = (const uint8_t*)lua_reqlstring(L,2,&sz2);
	if (sz1!=sz2) luaL_error(L, "string lengths must be the same\n");
	uint8_t *d3 = lua_newuserdata(L, sz1);

	op(d1,d2,d3,sz1);

	lua_pushlstring(L,(char*)d3,sz1);
	lua_remove(L,-2);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_bxor(lua_State *L)
{
	return luac_bop(L,"bxor",bxor);
}
static int luacall_bor(lua_State *L)
{
	return luac_bop(L,"bor",bor);
}
static int luacall_band(lua_State *L)
{
	return luac_bop(L,"band",band);
}

static int luacall_hash(lua_State *L)
{
	// hash(hash_type, data) returns hash
	lua_check_argc(L,"hash",2);

	LUA_STACK_GUARD_ENTER(L)

	const char *s_hash_type =  luaL_checkstring(L,1);
	SHAversion sha_ver = lua_hash_type(L, s_hash_type);

	size_t data_len;
	const uint8_t *data = (uint8_t*)lua_reqlstring(L,2,&data_len);

	unsigned char hash[USHAMaxHashSize];
	USHAContext tcontext;
	if (USHAReset(&tcontext, sha_ver)!=shaSuccess || USHAInput(&tcontext, data, data_len)!=shaSuccess || USHAResult(&tcontext, hash)!=shaSuccess)
		luaL_error(L, "hash failure");

	lua_pushlstring(L,(char*)hash,USHAHashSize(sha_ver));

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_aes(lua_State *L)
{
	// aes(bEncrypt, key, in) returns out
	lua_check_argc(L,"aes",3);

	LUA_STACK_GUARD_ENTER(L)

	bool bEncrypt = lua_toboolean(L,1);
	size_t key_len;
	const uint8_t *key = (uint8_t*)lua_reqlstring(L,2,&key_len);
	if (key_len!=16 && key_len!=24 && key_len!=32)
		luaL_error(L, "aes: wrong key length %u. should be 16,24,32.", (unsigned)key_len);
	size_t input_len;
	const uint8_t *input = (uint8_t*)lua_reqlstring(L,3,&input_len);
	if (input_len!=16)
		luaL_error(L, "aes: wrong data length %u. should be 16.", (unsigned)input_len);

	aes_context ctx;
	uint8_t output[16];
	if (aes_setkey(&ctx, bEncrypt, key, key_len) || aes_cipher(&ctx, input, output))
		lua_pushnil(L);
	else
		lua_pushlstring(L,(const char*)output,sizeof(output));

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_aes_gcm(lua_State *L)
{
	// aes_gcm(bEncrypt, key, iv, in, [additional_data]) returns out, atag
	lua_check_argc_range(L,"aes_gcm",4,5);

	LUA_STACK_GUARD_ENTER(L)

	int argc = lua_gettop(L);
	bool bEncrypt = lua_toboolean(L,1);
	size_t key_len;
	const uint8_t *key = (uint8_t*)lua_reqlstring(L,2,&key_len);
	if (key_len!=16 && key_len!=24 && key_len!=32)
		luaL_error(L, "aes_gcm: wrong key length %u. should be 16,24,32.", (unsigned)key_len);
	size_t iv_len;
	const uint8_t *iv = (uint8_t*)lua_reqlstring(L,3,&iv_len);
	if (!iv_len)
		luaL_error(L, "aes_gcm: zero iv length");
	size_t input_len;
	const uint8_t *input = (uint8_t*)lua_reqlstring(L,4,&input_len);
	size_t add_len=0;
	const uint8_t *add = lua_isnoneornil(L,5) ? NULL : (uint8_t*)lua_reqlstring(L,5,&add_len);

	uint8_t atag[16];
	uint8_t *output = lua_newuserdata(L, input_len);

	if (aes_gcm_crypt(bEncrypt, output, input, input_len, key, key_len, iv, iv_len, add, add_len, atag, sizeof(atag)))
	{
		lua_pushnil(L);
		lua_pushnil(L);
	}
	else
	{
		lua_pushlstring(L,(const char*)output,input_len);
		lua_pushlstring(L,(const char*)atag,sizeof(atag));
	}
	lua_remove(L,-3);

	LUA_STACK_GUARD_RETURN(L,2)
}

static int luacall_aes_ctr(lua_State *L)
{
	// aes_ctr(key, iv, in) returns out
	lua_check_argc(L,"aes_ctr",3);

	LUA_STACK_GUARD_ENTER(L)

	size_t key_len;
	const uint8_t *key = (uint8_t*)lua_reqlstring(L,1,&key_len);
	if (key_len!=16 && key_len!=24 && key_len!=32)
		luaL_error(L, "aes_ctr: wrong key length %u. should be 16,24,32.", (unsigned)key_len);

	size_t iv_len;
	const uint8_t *iv = (uint8_t*)lua_reqlstring(L,2,&iv_len);
	if (iv_len!=16)
		luaL_error(L, "aes_ctr: wrong iv length %u. should be 16.", (unsigned)iv_len);

	size_t input_len;
	const uint8_t *input = (uint8_t*)luaL_checklstring(L,3,&input_len);

	uint8_t *output = lua_newuserdata(L, input_len);

	if (aes_ctr_crypt(key, key_len, iv, input, input_len, output))
		lua_pushnil(L);
	else
		lua_pushlstring(L,(const char*)output,input_len);

	lua_remove(L,-2);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_hkdf(lua_State *L)
{
	// hkdf(hash_type, salt, ikm, info, okm_len) returns okm
	// hash_type - string "sha224" or "sha256"
	lua_check_argc(L,"hkdf",5);

	LUA_STACK_GUARD_ENTER(L)

	const char *s_hash_type =  luaL_checkstring(L,1);
	SHAversion sha_ver = lua_hash_type(L, s_hash_type);
	size_t salt_len=0;
	const uint8_t *salt = lua_type(L,2) == LUA_TNIL ? NULL : (uint8_t*)luaL_checklstring(L,2,&salt_len);
	size_t ikm_len=0;
	const uint8_t *ikm = lua_type(L,3) == LUA_TNIL ? NULL : (uint8_t*)luaL_checklstring(L,3,&ikm_len);
	size_t info_len=0;
	const uint8_t *info = lua_type(L,4) == LUA_TNIL ? NULL : (uint8_t*)luaL_checklstring(L,4,&info_len);
	lua_Integer okm_len = luaL_checkinteger(L,5);
	if (okm_len<0) luaL_error(L, "hkdf: invalid arg");

	uint8_t *okm = lua_newuserdata(L, okm_len);

	if (hkdf(sha_ver, salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len))
		lua_pushnil(L);
	else
		lua_pushlstring(L,(const char*)okm, okm_len);

	lua_remove(L,-2);

	LUA_STACK_GUARD_RETURN(L,1)
}


static int luacall_getpid(lua_State *L)
{
	lua_check_argc(L,"getpid", 0);
	lua_pushinteger(L, getpid());
	return 1;
}
static int luacall_gettid(lua_State *L)
{
	lua_check_argc(L,"gettid", 0);
#ifdef __OpenBSD__
	lua_pushinteger(L, getthrid());
#elif defined(__FreeBSD__)
	long tid;
	if (thr_self(&tid))
		lua_pushnil(L);
	else
		lua_pushinteger(L, tid);
#elif defined(__linux__)
	lua_pushinteger(L, syscall(SYS_gettid));
#elif defined(__CYGWIN__)
	lua_pushinteger(L, GetCurrentThreadId());
#elif defined(__APPLE__)
	uint64_t tid;
	if (pthread_threadid_np(NULL, &tid))
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)tid);
#else
	// unsupported OS ?
	lua_pushnil(L);
#endif
	return 1;
}
static int luacall_uname(lua_State *L)
{
	lua_check_argc(L,"uname", 0);

	LUA_STACK_GUARD_ENTER(L)

	struct utsname udata;
	if (uname(&udata))
		lua_pushnil(L);
	else
	{
		lua_createtable(L, 0, 5);
		lua_pushf_str(L,"sysname", udata.sysname);
		lua_pushf_str(L,"nodename", udata.nodename);
		lua_pushf_str(L,"release", udata.release);
		lua_pushf_str(L,"version", udata.version);
		lua_pushf_str(L,"machine", udata.machine);
	}
	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_clock_gettime(lua_State *L)
{
	lua_check_argc(L,"clock_gettime", 0);

	LUA_STACK_GUARD_ENTER(L)

	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts))
	{
		lua_pushnil(L);
		lua_pushnil(L);
	}
	else
	{
		lua_pushlint(L, ts.tv_sec);
		lua_pushinteger(L, ts.tv_nsec);
	}

	LUA_STACK_GUARD_RETURN(L,2)
}
static int luacall_clock_getfloattime(lua_State *L)
{
	lua_check_argc(L,"clock_getfloattime", 0);

	LUA_STACK_GUARD_ENTER(L)

	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts))
		lua_pushnil(L);
	else
		lua_pushnumber(L, ts.tv_sec + ts.tv_nsec/1000000000.);

	LUA_STACK_GUARD_RETURN(L,1)
}

static void lua_mt_init_desync_ctx(lua_State *L)
{
	luaL_newmetatable(L, "desync_ctx");
	lua_pop(L, 1);
}
static t_lua_desync_context *lua_desync_ctx(lua_State *L)
{
	if (lua_isnil(L,1)) luaL_error(L, "missing ctx");
	t_lua_desync_context *ctx = (t_lua_desync_context *)luaL_checkudata(L, 1, "desync_ctx");
	if (!ctx->valid) luaL_error(L, "ctx is invalid");
	return ctx;
}
static void lua_desync_ctx_create(lua_State *L)
{
	if (!params.ref_desync_ctx)
	{
		LUA_STACK_GUARD_ENTER(L)

		t_lua_desync_context *ctx = (t_lua_desync_context *)lua_newuserdata(L, sizeof(t_lua_desync_context));
		memset(ctx, 0, sizeof(*ctx));
		luaL_getmetatable(L, "desync_ctx");
		lua_setmetatable(L, -2);
		params.ref_desync_ctx = luaL_ref(params.L, LUA_REGISTRYINDEX);

		LUA_STACK_GUARD_LEAVE(L,0)
	}
}
static void lua_desync_ctx_destroy(lua_State *L)
{
	if (params.ref_desync_ctx)
	{
		luaL_unref(L, LUA_REGISTRYINDEX, params.ref_desync_ctx);
		params.ref_desync_ctx = 0;
	}
}

static int luacall_instance_cutoff(lua_State *L)
{
	// out : instance_name.profile_number[0]
	// in  : instance_name.profile_number[1]

	lua_check_argc_range(L,"instance_cutoff",1,2);

	LUA_STACK_GUARD_ENTER(L)

	if (lua_isnil(L,1))
		// this can happen in orchestrated function. they do not have their own ctx and they cant cutoff
		DLOG("instance cutoff not possible because missing ctx\n");
	else
	{
		const t_lua_desync_context *ctx = lua_desync_ctx(L);

		int argc=lua_gettop(L);
		bool bIn,bOut;
		if (argc>=2 && lua_type(L,2)!=LUA_TNIL)
		{
			luaL_checktype(L,2,LUA_TBOOLEAN);
			bOut = lua_toboolean(L,2);
			bIn = !bOut;
		}
		else
			bIn = bOut = true;
		if (ctx->ctrack)
		{
			DLOG("instance cutoff for '%s' in=%u out=%u\n",ctx->instance,bIn,bOut);
			lua_rawgeti(L,LUA_REGISTRYINDEX,ctx->ctrack->lua_instance_cutoff);
			lua_getfield(L,-1,ctx->instance);
			if (!lua_istable(L,-1))
			{
				lua_pop(L,1);
				lua_pushf_table(L,ctx->instance);
				lua_getfield(L,-1,ctx->instance);
			}
			lua_rawgeti(L,-1,ctx->dp->n);
			if (!lua_istable(L,-1))
			{
				lua_pop(L,1);
				lua_pushi_table(L,ctx->dp->n);
				lua_rawgeti(L,-1,ctx->dp->n);
			}
			if (bOut) lua_pushi_bool(L,0,true);
			if (bIn) lua_pushi_bool(L,1,true);
			lua_pop(L,3);
		}
		else
			DLOG("instance cutoff requested for '%s' in=%u out=%u but not possible without conntrack\n",ctx->instance,bIn,bOut);
	}

	LUA_STACK_GUARD_RETURN(L,0)
}

bool lua_instance_cutoff_check(lua_State *L, const t_lua_desync_context *ctx, bool bIn)
{
	bool b=false;

	// out : func_name.profile_number[0]
	// in  : func_name.profile_number[1]

	if (ctx->ctrack)
	{
		lua_rawgeti(L,LUA_REGISTRYINDEX,ctx->ctrack->lua_instance_cutoff);
		lua_getfield(L,-1,ctx->instance);
		if (!lua_istable(L,-1))
		{
			lua_pop(L,2);
			return false;
		}
		lua_rawgeti(L,-1,ctx->dp->n);
		if (!lua_istable(L,-1))
		{
			lua_pop(L,3);
			return false;
		}
		lua_rawgeti(L,-1,bIn);
		b = lua_toboolean(L,-1);
		lua_pop(L,4);
	}
	return b;
}

static int luacall_lua_cutoff(lua_State *L)
{
	lua_check_argc_range(L,"lua_cutoff",1,2);

	LUA_STACK_GUARD_ENTER(L)

	t_lua_desync_context *ctx = lua_desync_ctx(L);

	int argc=lua_gettop(L);
	bool bIn,bOut;
	if (argc>=2 && lua_type(L,2)!=LUA_TNIL)
	{
		luaL_checktype(L,2,LUA_TBOOLEAN);
		bOut = lua_toboolean(L,2);
		bIn = !bOut;
	}
	else
		bIn = bOut = true;

	if (ctx->ctrack)
	{
		DLOG("lua cutoff from '%s' in=%u out=%u\n",ctx->instance,bIn,bOut);
		// lua cutoff is one way transition
		if (bIn) ctx->ctrack->b_lua_in_cutoff = true;
		if (bOut) ctx->ctrack->b_lua_out_cutoff = true;
	}
	else
		DLOG("lua cutoff requested from '%s' in=%u out=%u but not possible without conntrack\n",ctx->instance,bIn,bOut);

	LUA_STACK_GUARD_RETURN(L,0)
}

static int luacall_execution_plan(lua_State *L)
{
	lua_check_argc(L,"execution_plan",1);

	LUA_STACK_GUARD_ENTER(L)

	t_lua_desync_context *ctx = lua_desync_ctx(L);

	lua_newtable(L);

	struct func_list *func;
	char instance[256], plsl[2048];
	struct packet_range *range;
	unsigned int n=1;
	t_l7payload pl;
	const char *pls;

	LIST_FOREACH(func, &ctx->dp->lua_desync, next)
	{
		if (n > ctx->func_n)
		{
			desync_instance(func->func, ctx->dp->n, n, instance, sizeof(instance));
			range = ctx->incoming ? &func->range_in : &func->range_out;

			lua_pushinteger(L, n - ctx->func_n);
			lua_createtable(L, 0, 7);

			lua_pushf_args(L,&func->args, -1, false);
			lua_pushf_str(L,"func", func->func);
			lua_pushf_int(L,"func_n", n);
			lua_pushf_str(L,"func_instance", instance);
			lua_pushf_range(L,"range", range);

			lua_pushstring(L, "payload");
			lua_newtable(L);
			if (func->payload_type==L7P_ALL)
			{
				lua_pushliteral(L,"all");
				lua_pushboolean(L,true);
				lua_rawset(L,-3);
			}
			else
			{
				for (pl=0 ; pl<L7P_LAST ; pl++)
				{
					if (func->payload_type & (1ULL<<pl))
					{
						if ((pls = l7payload_str(pl)))
						{
							lua_pushstring(L,pls);
							lua_pushboolean(L,true);
							lua_rawset(L,-3);
						}
					}
				}
			}
			lua_rawset(L,-3);

			if (l7_payload_str_list(func->payload_type, plsl, sizeof(plsl)))
				lua_pushf_str(L,"payload_filter", plsl);
			else
				lua_pushf_nil(L,"payload_filter");

			lua_rawset(L,-3);
		}
		n++;
	}

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_execution_plan_cancel(lua_State *L)
{
	lua_check_argc(L,"execution_plan_cancel",1);

	t_lua_desync_context *ctx = lua_desync_ctx(L);

	DLOG("execution plan cancel from '%s'\n",ctx->instance);

	ctx->cancel = true;
	return 0;
}


static int luacall_raw_packet(lua_State *L)
{
	lua_check_argc(L,"raw_packet",1);

	LUA_STACK_GUARD_ENTER(L)

	const t_lua_desync_context *ctx = lua_desync_ctx(L);

	lua_pushlstring(L, (const char*)ctx->dis->data_pkt, ctx->dis->len_pkt);

	LUA_STACK_GUARD_RETURN(L,1)
}


void lua_pushf_nil(lua_State *L, const char *field)
{
	lua_pushstring(L, field);
	lua_pushnil(L);
	lua_rawset(L,-3);
}
void lua_pushi_nil(lua_State *L, lua_Integer idx)
{
	lua_pushinteger(L, idx);
	lua_pushnil(L);
	lua_rawset(L,-3);
}
void lua_pushf_int(lua_State *L, const char *field, lua_Integer v)
{
	lua_pushstring(L, field);
	lua_pushlint(L, v);
	lua_rawset(L,-3);
}
void lua_pushi_int(lua_State *L, lua_Integer idx, lua_Integer v)
{
	lua_pushinteger(L, idx);
	lua_pushlint(L, v);
	lua_rawset(L,-3);
}
void lua_pushf_lint(lua_State *L, const char *field, int64_t v)
{
	lua_pushstring(L, field);
	lua_pushlint(L, v);
	lua_rawset(L,-3);
}
void lua_pushi_lint(lua_State *L, lua_Integer idx, int64_t v)
{
	lua_pushinteger(L, idx);
	lua_pushlint(L, v);
	lua_rawset(L,-3);
}
void lua_pushf_number(lua_State *L, const char *field, lua_Number v)
{
	lua_pushstring(L, field);
	lua_pushnumber(L, v);
	lua_rawset(L,-3);
}
void lua_pushi_number(lua_State *L, lua_Integer idx, lua_Number v)
{
	lua_pushinteger(L, idx);
	lua_pushnumber(L, v);
	lua_rawset(L,-3);
}
void lua_pushf_bool(lua_State *L, const char *field, bool b)
{
	lua_pushstring(L, field);
	lua_pushboolean(L, b);
	lua_rawset(L,-3);
}
void lua_pushi_bool(lua_State *L, lua_Integer idx, bool b)
{
	lua_pushinteger(L, idx);
	lua_pushboolean(L, b);
	lua_rawset(L,-3);
}
void lua_pushf_str(lua_State *L, const char *field, const char *str)
{
	lua_pushstring(L, field);
	lua_pushstring(L, str); // pushes nil if str==NULL
	lua_rawset(L,-3);
}
void lua_pushi_str(lua_State *L, lua_Integer idx, const char *str)
{
	lua_pushinteger(L, idx);
	lua_pushstring(L, str); // pushes nil if str==NULL
	lua_rawset(L,-3);
}
void lua_pushf_lstr(lua_State *L, const char *field, const char *str, size_t size)
{
	lua_pushstring(L, field);
	lua_pushlstring(L, str, size);
	lua_rawset(L,-3);
}
void lua_pushi_lstr(lua_State *L, lua_Integer idx, const char *str, size_t size)
{
	lua_pushinteger(L, idx);
	lua_pushlstring(L, str, size);
	lua_rawset(L,-3);
}
void lua_push_raw(lua_State *L, const void *v, size_t l)
{
	if (v)
		lua_pushlstring(L, (char*)v, l);
	else
		lua_pushnil(L);
}
void lua_pushf_raw(lua_State *L, const char *field, const void *v, size_t l)
{
	lua_pushstring(L, field);
	lua_push_raw(L, v,l);
	lua_rawset(L,-3);
}
void lua_pushi_raw(lua_State *L, lua_Integer idx, const void *v, size_t l)
{
	lua_pushinteger(L, idx);
	lua_push_raw(L,v,l);
	lua_rawset(L,-3);
}
void lua_pushf_reg(lua_State *L, const char *field, int ref)
{
	lua_pushstring(L, field);
	lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
	lua_rawset(L, -3);
}
void lua_pushf_lud(lua_State *L, const char *field, void *p)
{
	lua_pushstring(L, field);
	lua_pushlightuserdata(L, p);
	lua_rawset(L,-3);
}
void lua_pushf_table(lua_State *L, const char *field)
{
	lua_pushstring(L, field);
	lua_newtable(L);
	lua_rawset(L,-3);
}
void lua_pushi_table(lua_State *L, lua_Integer idx)
{
	lua_pushinteger(L, idx);
	lua_newtable(L);
	lua_rawset(L,-3);
}
void lua_pushf_global(lua_State *L, const char *field, const char *global)
{
	lua_pushstring(L, field);
	lua_getglobal(L, global);
	lua_rawset(L,-3);
}

void lua_push_blob(lua_State *L, int idx_desync, const char *blob)
{
	lua_getfield(L, idx_desync, blob);
	if (lua_type(L,-1)==LUA_TNIL)
	{
		lua_pop(L,1);
		lua_getglobal(L, blob);
	}
	lua_tostring(L,-1);
}
void lua_pushf_blob(lua_State *L, int idx_desync, const char *field, const char *blob)
{
	lua_pushstring(L, field);
	lua_push_blob(L, idx_desync, blob);
	lua_rawset(L,-3);
}

void lua_push_ipaddr(lua_State *L, const struct sockaddr *sa)
{
	switch(sa ? sa->sa_family : 0)
	{
		case AF_INET:
			lua_pushlstring(L, (const char*)&((struct sockaddr_in*)sa)->sin_addr, sizeof(struct in_addr));
			break;
		case AF_INET6:
			lua_pushlstring(L, (const char*)&((struct sockaddr_in6*)sa)->sin6_addr, sizeof(struct in6_addr));
			break;
		default:
			lua_pushnil(L);
	}
}
void lua_pushf_ipaddr(lua_State *L, const char *field, const struct sockaddr *sa)
{
	lua_pushstring(L, field);
	lua_push_ipaddr(L,sa);
	lua_rawset(L,-3);
}
void lua_pushi_ipaddr(lua_State *L, lua_Integer idx, const struct sockaddr *sa)
{
	lua_pushinteger(L, idx);
	lua_push_ipaddr(L,sa);
	lua_rawset(L,-3);
}

void lua_pushf_tcphdr_options(lua_State *L, const struct tcphdr *tcp, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_pushliteral(L,"options");
	lua_newtable(L);

	uint8_t *t = (uint8_t*)(tcp+1);
	uint8_t *end = (uint8_t*)tcp + (tcp->th_off<<2);
	uint8_t opt;
	if ((end-(uint8_t*)tcp) > len) end=(uint8_t*)tcp + len;
	lua_Integer idx=1;
	while(t<end)
	{
		opt = *t;
		if (opt==TCP_KIND_NOOP || opt==TCP_KIND_END)
		{
			lua_pushinteger(L,idx);
			lua_newtable(L);
			lua_pushf_int(L,"kind",opt);
			t++;
		}
		else
		{
			if ((t+1)>=end || t[1]<2 || (t+t[1])>end) break;
			lua_pushinteger(L,idx);
			lua_newtable(L);
			lua_pushf_int(L,"kind",opt);
			lua_pushf_raw(L,"data",t+2,t[1]-2);
			t+=t[1];
		}
		lua_rawset(L,-3);
		if (opt==TCP_KIND_END) break;
		idx++;
	}

	lua_rawset(L,-3);

	LUA_STACK_GUARD_LEAVE(L, 0)
}

void lua_push_tcphdr(lua_State *L, const struct tcphdr *tcp, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)

	if (tcp && len>=sizeof(struct tcphdr))
	{
		lua_createtable(L, 0, 11);
		lua_pushf_int(L,"th_sport",ntohs(tcp->th_sport));
		lua_pushf_int(L,"th_dport",ntohs(tcp->th_dport));
		lua_pushf_lint(L,"th_seq",ntohl(tcp->th_seq));
		lua_pushf_lint(L,"th_ack",ntohl(tcp->th_ack));
		lua_pushf_int(L,"th_x2",tcp->th_x2);
		lua_pushf_int(L,"th_off",tcp->th_off);
		lua_pushf_int(L,"th_flags",tcp->th_flags);
		lua_pushf_int(L,"th_win",ntohs(tcp->th_win));
		lua_pushf_int(L,"th_sum",ntohs(tcp->th_sum));
		lua_pushf_int(L,"th_urp",ntohs(tcp->th_urp));
		lua_pushf_tcphdr_options(L,tcp,len);
	}
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_LEAVE(L, 1)
}
void lua_pushf_tcphdr(lua_State *L, const struct tcphdr *tcp, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_pushliteral(L, "tcp");
	lua_push_tcphdr(L,tcp,len);
	lua_rawset(L,-3);

	LUA_STACK_GUARD_LEAVE(L, 0)
}
static int luacall_dissect_tcphdr(lua_State *L)
{
	// dissect_tcphdr(tcphdr_data)
	lua_check_argc(L,"dissect_tcphdr",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (const uint8_t*)lua_reqlstring(L, 1, &len);

	lua_push_tcphdr(L, (struct tcphdr*)data, len);

	LUA_STACK_GUARD_RETURN(L,1)
}
void lua_push_udphdr(lua_State *L, const struct udphdr *udp, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)

	if (udp && len>=sizeof(struct udphdr))
	{
		lua_createtable(L, 0, 4);
		lua_pushf_int(L,"uh_sport",ntohs(udp->uh_sport));
		lua_pushf_int(L,"uh_dport",ntohs(udp->uh_dport));
		lua_pushf_int(L,"uh_ulen",ntohs(udp->uh_ulen));
		lua_pushf_int(L,"uh_sum",ntohs(udp->uh_sum));
	}
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_LEAVE(L, 1)
}
void lua_pushf_udphdr(lua_State *L, const struct udphdr *udp, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_pushliteral(L, "udp");
	lua_push_udphdr(L,udp,len);
	lua_rawset(L,-3);

	LUA_STACK_GUARD_LEAVE(L, 0)
}
static int luacall_dissect_udphdr(lua_State *L)
{
	// dissect_udphdr(udphdr_data)
	lua_check_argc(L,"dissect_udphdr",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (const uint8_t*)lua_reqlstring(L, 1, &len);

	lua_push_udphdr(L, (struct udphdr*)data, len);

	LUA_STACK_GUARD_RETURN(L,1)
}
void lua_push_icmphdr(lua_State *L, const struct icmp46 *icmp, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)

	if (icmp && len>=sizeof(struct icmp46))
	{
		lua_createtable(L, 0, 4);
		lua_pushf_int(L,"icmp_type",icmp->icmp_type);
		lua_pushf_int(L,"icmp_code",icmp->icmp_code);
		lua_pushf_int(L,"icmp_cksum",ntohs(icmp->icmp_cksum));
		lua_pushf_lint(L,"icmp_data",ntohl(icmp->data.data32));
	}
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_LEAVE(L, 1)
}
void lua_pushf_icmphdr(lua_State *L, const struct icmp46 *icmp, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_pushliteral(L, "icmp");
	lua_push_icmphdr(L,icmp,len);
	lua_rawset(L,-3);

	LUA_STACK_GUARD_LEAVE(L, 0)
}
static int luacall_dissect_icmphdr(lua_State *L)
{
	// dissect_icmphdr(icmphdr_data)
	lua_check_argc(L,"dissect_icmphdr",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (const uint8_t*)lua_reqlstring(L, 1, &len);

	lua_push_icmphdr(L, (struct icmp46*)data, len);

	LUA_STACK_GUARD_RETURN(L,1)
}
void lua_push_iphdr(lua_State *L, const struct ip *ip, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)
	if (ip && len>=sizeof(struct ip))
	{
		uint16_t hl = ip->ip_hl<<2;
		bool b_has_opt = hl>sizeof(struct ip) && hl<=len;
		lua_createtable(L, 0, 11+b_has_opt);
		lua_pushf_int(L,"ip_v",ip->ip_v);
		lua_pushf_int(L,"ip_hl",ip->ip_hl);
		lua_pushf_int(L,"ip_tos",ip->ip_tos);
		lua_pushf_int(L,"ip_len",ntohs(ip->ip_len));
		lua_pushf_int(L,"ip_id",ntohs(ip->ip_id));
		lua_pushf_int(L,"ip_off",ntohs(ip->ip_off));
		lua_pushf_int(L,"ip_ttl",ip->ip_ttl);
		lua_pushf_int(L,"ip_p",ip->ip_p);
		lua_pushf_int(L,"ip_sum",ntohs(ip->ip_sum));
		lua_pushf_raw(L,"ip_src",&ip->ip_src,sizeof(struct in_addr));
		lua_pushf_raw(L,"ip_dst",&ip->ip_dst,sizeof(struct in_addr));
		if (b_has_opt)
			lua_pushf_raw(L,"options",(uint8_t*)(ip+1),hl-sizeof(struct ip));
	}
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_LEAVE(L, 1)
}
void lua_pushf_iphdr(lua_State *L, const struct ip *ip, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)
	lua_pushliteral(L, "ip");
	lua_push_iphdr(L,ip,len);
	lua_rawset(L,-3);
	LUA_STACK_GUARD_LEAVE(L, 0)
}
static int luacall_dissect_iphdr(lua_State *L)
{
	// dissect_iphdr(iphdr_data)
	lua_check_argc(L,"dissect_iphdr",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (const uint8_t*)lua_reqlstring(L, 1, &len);

	lua_push_iphdr(L, (struct ip*)data, len);

	LUA_STACK_GUARD_RETURN(L,1)
}
void lua_pushf_ip6exthdr(lua_State *L, const struct ip6_hdr *ip6, size_t len)
{
	LUA_STACK_GUARD_ENTER(L);

	// assume ipv6 packet structure was already checked for validity
	size_t hdrlen;
	lua_Integer idx = 1;
	uint8_t HeaderType, *data;
	uint16_t plen;
	uint16_t fr_off=0;
	bool fr=false;

	lua_pushliteral(L, "exthdr");
	lua_newtable(L);
	if (len>=sizeof(struct ip6_hdr))
	{
		HeaderType = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		data=(uint8_t*)(ip6+1);
		len-=sizeof(struct ip6_hdr);
		plen = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
		if (plen < len) len = plen;
		while (len && !(fr && fr_off)) // need at least one byte for NextHeader field. stop after fragment header if not first fragment
		{
			switch (HeaderType)
			{
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
			case IPPROTO_MH: // mobility header
			case IPPROTO_HIP: // Host Identity Protocol Version v2
			case IPPROTO_SHIM6:
				if (len < 2) goto end; // error
				hdrlen = 8 + (data[1] << 3);
				break;
			case IPPROTO_FRAGMENT: // fragment. length fixed to 8, hdrlen field defined as reserved
				hdrlen = 8;
				if (len < hdrlen) goto end;
				fr_off = ntohs(((struct ip6_frag*)data)->ip6f_offlg & IP6F_OFF_MASK);
				fr = ((struct ip6_frag*)data)->ip6f_offlg & (IP6F_OFF_MASK|IP6F_MORE_FRAG);
				break;
			case IPPROTO_AH:
				// special case. length in ah header is in 32-bit words minus 2
				if (len < 2) goto end; // error
				hdrlen = 8 + (data[1] << 2);
				break;
			case IPPROTO_NONE: // no next header
			default:
				// we found some meaningful payload. it can be tcp, udp, icmp or some another exotic shit
				goto end;
			}
			if (len < hdrlen) goto end; // error

			lua_pushinteger(L, idx++);
			lua_createtable(L, 0, 3);
			lua_pushf_int(L,"type", HeaderType);
			HeaderType = *data;
			lua_pushf_int(L,"next", HeaderType);
			lua_pushf_raw(L,"data",data+2,hdrlen-2);
			lua_rawset(L,-3);

			// advance to the next header location
			len -= hdrlen;
			data += hdrlen;
		}
	}

end:
	lua_rawset(L,-3);

	LUA_STACK_GUARD_LEAVE(L, 0)
}
void lua_push_ip6hdr(lua_State *L, const struct ip6_hdr *ip6, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)

	if (ip6 && len>=sizeof(struct ip6_hdr))
	{
		lua_createtable(L, 0, 7);
		lua_pushf_lint(L,"ip6_flow",ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow));
		lua_pushf_lint(L,"ip6_plen",ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
		lua_pushf_int(L,"ip6_nxt",ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
		lua_pushf_int(L,"ip6_hlim",ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
		lua_pushf_raw(L,"ip6_src",&ip6->ip6_src,sizeof(struct in6_addr));
		lua_pushf_raw(L,"ip6_dst",&ip6->ip6_dst,sizeof(struct in6_addr));
		lua_pushf_ip6exthdr(L,ip6,len);
	}
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_LEAVE(L, 1)
}
void lua_pushf_ip6hdr(lua_State *L, const struct ip6_hdr *ip6, size_t len)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_pushliteral(L, "ip6");
	lua_push_ip6hdr(L,ip6,len);
	lua_rawset(L,-3);

	LUA_STACK_GUARD_LEAVE(L, 0)
}
static int luacall_dissect_ip6hdr(lua_State *L)
{
	// dissect_iphdr(ip6hdr_data)
	lua_check_argc(L,"dissect_ip6hdr",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (const uint8_t*)lua_reqlstring(L, 1, &len);

	lua_push_ip6hdr(L, (struct ip6_hdr*)data, len);

	LUA_STACK_GUARD_RETURN(L,1)
}
void lua_push_dissect(lua_State *L, const struct dissect *dis)
{
	LUA_STACK_GUARD_ENTER(L)

	if (dis)
	{
		lua_createtable(L, 0, 10+dis->frag);
		lua_pushf_int(L,"l4proto",dis->proto);
		lua_pushf_int(L,"transport_len",dis->transport_len);
		lua_pushf_int(L,"l3_len",dis->len_l3);
		lua_pushf_int(L,"l4_len",dis->len_l4);
		lua_pushf_raw(L,"payload",dis->data_payload,dis->len_payload);
		if (dis->frag) lua_pushf_int(L,"frag_off",dis->frag_off);
		lua_pushf_iphdr(L,dis->ip, dis->len_l3);
		lua_pushf_ip6hdr(L,dis->ip6, dis->len_l3);
		lua_pushf_tcphdr(L,dis->tcp, dis->len_l4);
		lua_pushf_udphdr(L,dis->udp, dis->len_l4);
		lua_pushf_icmphdr(L,dis->icmp, dis->len_l4);
	}
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_LEAVE(L, 1)
}
void lua_pushf_dissect(lua_State *L, const struct dissect *dis)
{
	lua_pushliteral(L, "dis");
	lua_push_dissect(L, dis);
	lua_rawset(L,-3);
}

void lua_pushf_ctrack_pos(lua_State *L, const t_ctrack *ctrack, const t_ctrack_position *pos)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_pushf_lint(L,"pcounter", pos->pcounter);
	lua_pushf_lint(L,"pdcounter", pos->pdcounter);
	lua_pushf_lint(L,"pbcounter", pos->pbcounter);
	if (pos->ip6flow) lua_pushf_int(L,"ip6_flow", pos->ip6flow);
	if (ctrack->pos.ipproto == IPPROTO_TCP)
	{
		lua_pushliteral(L, "tcp");
		lua_createtable(L, 0, 11);
		lua_pushf_lint(L,"seq0", pos->seq0);
		lua_pushf_lint(L,"seq", pos->seq_last);
		lua_pushf_lint(L,"rseq", pos->seq_last - pos->seq0);
		lua_pushf_bool(L,"rseq_over_2G", pos->rseq_over_2G);
		lua_pushf_int(L,"pos", pos->pos - pos->seq0);
		lua_pushf_int(L,"uppos", pos->uppos - pos->seq0);
		lua_pushf_int(L,"uppos_prev", pos->uppos_prev - pos->seq0);
		lua_pushf_int(L,"winsize", pos->winsize);
		lua_pushf_int(L,"winsize_calc", pos->winsize_calc);
		lua_pushf_int(L,"scale", pos->scale);
		lua_pushf_int(L,"mss", pos->mss);
		lua_rawset(L,-3);
	}

	LUA_STACK_GUARD_LEAVE(L, 0)
}

void lua_push_ctrack(lua_State *L, const t_ctrack *ctrack, const t_ctrack_positions *tpos, bool bIncoming)
{
	LUA_STACK_GUARD_ENTER(L)

	if (ctrack)
	{
		if (!tpos) tpos = &ctrack->pos;

		lua_createtable(L, 0, 9);

		if (ctrack->incoming_ttl)
			lua_pushf_int(L, "incoming_ttl", ctrack->incoming_ttl);
		lua_pushf_str(L, "l7proto", l7proto_str(ctrack->l7proto));
		lua_pushf_str(L, "hostname", ctrack->hostname);
		if (ctrack->hostname) lua_pushf_bool(L, "hostname_is_ip", ctrack->hostname_is_ip);
		lua_pushf_reg(L, "lua_state", ctrack->lua_state);
		lua_pushf_bool(L, "lua_in_cutoff", ctrack->b_lua_in_cutoff);
		lua_pushf_bool(L, "lua_out_cutoff", ctrack->b_lua_out_cutoff);
		lua_pushf_number(L, "t_start", (lua_Number)ctrack->t_start.tv_sec + ctrack->t_start.tv_nsec/1000000000.);

		lua_pushliteral(L, "pos");
		lua_createtable(L, 0, 5);

		// orig, reply related to connection logical direction
		// for tcp orig is client (who connects), reply is server (who listens). 
		// for orig is the first seen party, reply is another party
		lua_pushf_number(L, "dt",
			(lua_Number)tpos->t_last.tv_sec - (lua_Number)ctrack->t_start.tv_sec +
			(tpos->t_last.tv_nsec - ctrack->t_start.tv_nsec)/1000000000.);

		lua_pushliteral(L, "client");
		lua_newtable(L);
		lua_pushf_ctrack_pos(L, ctrack, &tpos->client);
		lua_rawset(L,-3);

		lua_pushliteral(L, "server");
		lua_newtable(L);
		lua_pushf_ctrack_pos(L, ctrack, &tpos->server);
		lua_rawset(L,-3);

		// direct and reverse are adjusted for server mode. in server mode orig and reply are exchanged.
		lua_pushliteral(L, "direct");
		lua_getfield(L, -2, (params.server ^ bIncoming) ? "server" : "client");
		lua_rawset(L,-3);

		lua_pushliteral(L, "reverse");
		lua_getfield(L, -2, (params.server ^ bIncoming) ? "client" : "server");
		lua_rawset(L,-3);

		lua_rawset(L,-3);
	}
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_LEAVE(L, 1)
}

void lua_pushf_ctrack(lua_State *L, const t_ctrack *ctrack, const t_ctrack_positions *tpos, bool bIncoming)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_pushliteral(L, "track");
	lua_push_ctrack(L, ctrack, tpos, bIncoming);
	lua_rawset(L,-3);

	LUA_STACK_GUARD_LEAVE(L, 0)
}

void lua_pushf_args(lua_State *L, const struct str2_list_head *args, int idx_desync, bool subst_prefix)
{
	// var=val - pass val string
	// var=%val - subst 'val' blob
	// var=#val - subst 'val' blob length
	// var=\#val - no subst, skip '\'
	// var=\%val - no subst, skip '\'

	LUA_STACK_GUARD_ENTER(L)

	struct str2_list *arg;
	const char *var, *val;

	idx_desync = lua_absindex(L, idx_desync);

	lua_pushliteral(L,"arg");
	lua_newtable(L);
	LIST_FOREACH(arg, args, next)
	{
		var = arg->str1;
		val = arg->str2 ? arg->str2 : "";
		if (subst_prefix)
		{
			if (val[0]=='\\' && (val[1]=='%' || val[1]=='#'))
				// escape char
				lua_pushf_str(L, var, val+1);
			else if (val[0]=='%')
				lua_pushf_blob(L, idx_desync, var, val+1);
			else if (val[0]=='#')
			{
				lua_push_blob(L, idx_desync, val+1);
				lua_Integer len = lua_rawlen(L, -1);
				lua_pop(L,1);
				lua_pushstring(L, var);
				lua_pushinteger(L, len);
				lua_tostring(L,-1); // force string type in arg
				lua_rawset(L,-3);
			}
			else
				lua_pushf_str(L, var, val);
		}
		else
			lua_pushf_str(L, var, val);
	}
	lua_rawset(L,-3);

	LUA_STACK_GUARD_LEAVE(L, 0)
}
void lua_pushf_pos(lua_State *L, const char *name, const struct packet_pos *pos)
{
	LUA_STACK_GUARD_ENTER(L)

	char smode[2]="?";
	lua_pushf_table(L,name);
	lua_getfield(L, -1, name);
	*smode=pos->mode;
	lua_pushf_str(L, "mode",smode);
	lua_pushf_lint(L, "pos",pos->pos);
	lua_pop(L,1);

	LUA_STACK_GUARD_LEAVE(L, 0)
}
void lua_pushf_range(lua_State *L, const char *name, const struct packet_range *range)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_pushf_table(L, name);
	lua_getfield(L, -1, name);
	lua_pushf_bool(L, "upper_cutoff",range->upper_cutoff);
	lua_pushf_pos(L, "from", &range->from);
	lua_pushf_pos(L, "to", &range->to);
	lua_pop(L,1);

	LUA_STACK_GUARD_LEAVE(L, 0)
}


static void lua_reconstruct_extract_options(lua_State *L, int idx, bool *keepsum, bool *badsum, bool *ip6_preserve_next, uint8_t *ip6_last_proto)
{
	if (lua_isnoneornil(L,idx))
	{
		if (keepsum) *keepsum = false;
		if (badsum) *badsum = false;
		if (ip6_preserve_next) *ip6_preserve_next = false;
		if (ip6_last_proto) *ip6_last_proto = IPPROTO_NONE;
	}
	else
	{
		luaL_checktype(L, idx, LUA_TTABLE);
		if (keepsum)
		{
			lua_getfield(L, idx,"keepsum");
			*keepsum = lua_type(L,-1)!=LUA_TNIL && (lua_type(L,-1)!=LUA_TBOOLEAN || lua_toboolean(L,-1));
			lua_pop(L,1);
		}
		if (badsum)
		{
			lua_getfield(L, idx,"badsum");
			*badsum = lua_type(L,-1)!=LUA_TNIL && (lua_type(L,-1)!=LUA_TBOOLEAN || lua_toboolean(L,-1));
			lua_pop(L,1);
		}
		if (ip6_preserve_next)
		{
			lua_getfield(L, idx,"ip6_preserve_next");
			*ip6_preserve_next = lua_type(L,-1)!=LUA_TNIL && (lua_type(L,-1)!=LUA_TBOOLEAN || lua_toboolean(L,-1));
			lua_pop(L,1);
		}
		if (ip6_last_proto)
		{
			lua_getfield(L, idx,"ip6_last_proto");
			*ip6_last_proto = lua_type(L,-1)==LUA_TNIL ? IPPROTO_NONE : (uint8_t)lua_tointeger(L,-1);
			lua_pop(L,1);
		}
	}
}


static bool lua_reconstruct_ip6exthdr(lua_State *L, int idx, struct ip6_hdr *ip6, size_t *len, uint8_t proto, bool preserve_next)
{
	LUA_STACK_GUARD_ENTER(L)
	// proto = last header type
	if (*len<sizeof(struct ip6_hdr)) return false;

	uint8_t *last_proto = &ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	size_t filled = sizeof(struct ip6_hdr);
	lua_getfield(L,idx,"exthdr");
	if (lua_type(L,-1)==LUA_TTABLE)
	{
		lua_Integer idx=0;
		uint8_t next, type, *p, *data = (uint8_t*)(ip6+1);
		size_t l, left;

	 	left = *len - filled;

		for(;;)
		{
			lua_rawgeti(L,-1,++idx);
			if (lua_type(L,-1)==LUA_TNIL)
			{
				lua_pop(L, 1);
				break;
			}
			else
			{
				if (lua_type(L,-1)!=LUA_TTABLE) goto err;

				lua_getfield(L,-1, "type");
				if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
				type = (uint8_t)lua_tointeger(L,-1);
				lua_pop(L, 1);

				lua_getfield(L,-1, "next");
				next = lua_type(L,-1)==LUA_TNUMBER ? (uint8_t)lua_tointeger(L,-1) : IPPROTO_NONE;
				lua_pop(L, 1);

				lua_getfield(L,-1, "data");
				if (lua_type(L,-1)!=LUA_TSTRING) goto err;
				if (!(p=(uint8_t*)lua_tolstring(L,-1,&l))) l=0;

				if (l<6 || (l+2)>left) goto err;
				if (type==IPPROTO_AH)
				{
					if (l>=1024 || ((l+2) & 3)) goto err;
					memcpy(data+2,p,l);
					l+=2;
					data[1] = (l>>2)-2;
				}
				else
				{
					if (l>=2048 || ((l+2) & 7)) goto err;
					memcpy(data+2,p,l);
					l+=2;
					data[1] = (l>>3)-1;
				}

				data[0] = next; // may be overwritten later
				if (!preserve_next) *last_proto = type;
				last_proto = data; // first byte of header holds type
				left -= l; data += l; filled += l;
				lua_pop(L, 2);
			}
		}
	}

	// set last header proto
	if (!preserve_next) *last_proto = proto;

	*len = filled;
	lua_pop(L, 1);
	LUA_STACK_GUARD_LEAVE(L, 0)
	return true;
err:
	LUA_STACK_GUARD_UNWIND(L)
	return false;
}
bool lua_reconstruct_ip6hdr(lua_State *L, int idx, struct ip6_hdr *ip6, size_t *len, uint8_t last_proto, bool preserve_next)
{
	LUA_STACK_GUARD_ENTER(L)

	const char *p;
	size_t l;
	if (*len<sizeof(struct ip6_hdr) || lua_type(L,idx)!=LUA_TTABLE) return false;

	idx = lua_absindex(L, idx);

	lua_getfield(L,idx,"ip6_flow");
	ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(lua_type(L,-1)==LUA_TNUMBER ? (uint32_t)lua_tolint(L,-1) : 0x60000000);
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip6_nxt");
	ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = (uint8_t)lua_tointeger(L,-1);
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip6_hlim");
	ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = (uint8_t)lua_tointeger(L,-1);
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip6_src");
	if (lua_type(L,-1)!=LUA_TSTRING) goto err;
	p = lua_tolstring(L,-1,&l);
	if (!p || l!=sizeof(struct in6_addr)) goto err;
	ip6->ip6_src = *(struct in6_addr*)p;
	lua_pop(L, 1);
	
	lua_getfield(L,idx,"ip6_dst");
	if (lua_type(L,-1)!=LUA_TSTRING) goto err;
	p = lua_tolstring(L,-1,&l);
	if (!p || l!=sizeof(struct in6_addr)) goto err;
	ip6->ip6_dst = *(struct in6_addr*)p;
	lua_pop(L, 1);

	bool have_plen = false;
	lua_getfield(L,idx,"ip6_plen");
	switch (lua_type(L,-1))
	{
		case LUA_TNIL:
			break;
		case LUA_TNUMBER:
			ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons((uint16_t)luaL_checkinteger(L,-1));
			have_plen = true;
			break;
		default:
			luaL_error(L,"reconstruct_ip6hdr: ip6_plen wrong type");
	}
	lua_pop(L, 1);

	bool b = lua_reconstruct_ip6exthdr(L, idx, ip6, len, last_proto, preserve_next);
	if (b && !have_plen) ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons((uint16_t)(*len-sizeof(struct ip6_hdr)));

	LUA_STACK_GUARD_LEAVE(L, 0)
	return b;
err:
	lua_pop(L, 1);
	LUA_STACK_GUARD_LEAVE(L, 0)
	return false;
}

static int luacall_reconstruct_ip6hdr(lua_State *L)
{
	lua_check_argc_range(L,"reconstruct_ip6hdr",1,2);

	LUA_STACK_GUARD_ENTER(L)

	char data[512];
	size_t len=sizeof(data);
	uint8_t last_proto;
	bool preserve_next;

	lua_reconstruct_extract_options(L, 2, NULL, NULL, &preserve_next, &last_proto);

	if (!lua_reconstruct_ip6hdr(L, 1,(struct ip6_hdr*)data, &len, last_proto, preserve_next))
		luaL_error(L, "invalid data for ip6hdr");
	lua_pushlstring(L,data,len);

	LUA_STACK_GUARD_RETURN(L,1)
}

bool lua_reconstruct_iphdr(lua_State *L, int idx, struct ip *ip, size_t *len)
{
	const char *p;
	size_t l, lopt=0;

	LUA_STACK_GUARD_ENTER(L)

	if (*len<sizeof(struct ip) || lua_type(L,idx)!=LUA_TTABLE) return false;

	ip->ip_v = IPVERSION;

	lua_getfield(L,idx,"ip_tos");
	ip->ip_tos = (uint8_t)lua_tointeger(L,-1);
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip_len");
	ip->ip_len = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip_id");
	ip->ip_id = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip_off");
	ip->ip_off = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip_ttl");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	ip->ip_ttl = (uint8_t)lua_tointeger(L,-1);
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip_p");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	ip->ip_p = (uint8_t)lua_tointeger(L,-1);
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip_src");
	if (lua_type(L,-1)!=LUA_TSTRING) goto err;
	p = lua_tolstring(L,-1,&l);
	if (!p || l!=sizeof(struct in_addr)) goto err;
	ip->ip_src = *(struct in_addr*)p;
	lua_pop(L, 1);

	lua_getfield(L,idx,"ip_dst");
	if (lua_type(L,-1)!=LUA_TSTRING) goto err;
	p = lua_tolstring(L,-1,&l);
	if (!p || l!=sizeof(struct in_addr)) goto err;
	ip->ip_dst = *(struct in_addr*)p;
	lua_pop(L, 1);

	lua_getfield(L,idx,"options");
	if (lua_type(L,-1)==LUA_TSTRING)
	{
		p = lua_tolstring(L,-1,&lopt);
		if (p && lopt)
		{
			if (lopt>40 || ((sizeof(struct ip) + ((lopt+3)&~3)) > *len)) goto err;
			memcpy(ip+1,p,lopt);
			memset(((uint8_t*)ip) + sizeof(struct ip) + lopt, 0, (4-(lopt&3))&3);
			lopt = (lopt+3) & ~3;
		}
	}
	lua_pop(L, 1);

	*len = sizeof(struct ip) + lopt;
	ip->ip_hl = *len >> 2;

	ip4_fix_checksum(ip);

	LUA_STACK_GUARD_LEAVE(L, 0)
	return true;
err:
	lua_pop(L, 1);
	LUA_STACK_GUARD_LEAVE(L, 0)
	return false;
}
static int luacall_reconstruct_iphdr(lua_State *L)
{
	lua_check_argc(L,"reconstruct_iphdr",1);

	LUA_STACK_GUARD_ENTER(L)

	char data[60];
	size_t l = sizeof(data);
	if (!lua_reconstruct_iphdr(L,1,(struct ip*)&data,&l))
		luaL_error(L, "invalid data for iphdr");
	lua_pushlstring(L,data,l);

	LUA_STACK_GUARD_RETURN(L,1)
}

static bool lua_reconstruct_tcphdr_options(lua_State *L, int idx, struct tcphdr *tcp, size_t *len)
{
	if (*len<sizeof(struct tcphdr)) return false;

	LUA_STACK_GUARD_ENTER(L)

	uint8_t filled = sizeof(struct tcphdr);

	lua_getfield(L,idx,"options");
	if (lua_type(L,-1)==LUA_TTABLE)
	{
		lua_Integer idx=0;
		uint8_t *p, *data = (uint8_t*)(tcp+1);
		size_t l, left;
		uint8_t kind;

	 	left = *len - filled;
		if (left>40) left=40; // max size of tcp options

		for (;;)
		{
			lua_rawgeti(L,-1,++idx);
			if (lua_type(L,-1)==LUA_TNIL)
			{
				lua_pop(L, 1);
				break;
			}
			else
			{
				// uses 'key' (at index -2) and 'value' (at index -1)

				if (!left || lua_type(L,-1)!=LUA_TTABLE) goto err;

				lua_getfield(L,-1, "kind");
				if (lua_type(L,-1)!=LUA_TNUMBER) goto err;

				kind = (uint8_t)lua_tointeger(L,-1);
				lua_pop(L, 1);

				switch(kind)
				{
					case TCP_KIND_END:
						*data = kind; data++; left--; filled++;
						lua_pop(L, 1);
						goto end;
					case TCP_KIND_NOOP:
						*data = kind; data++; left--; filled++;
						break;
					default:
						lua_getfield(L,-1, "data");
						l = 0;
						p = lua_type(L,-1)==LUA_TSTRING ? (uint8_t*)lua_tolstring(L,-1,&l) : NULL;
						if ((2+l)>left) goto err;
						if (p) memcpy(data+2,p,l);
						l+=2;
						data[0] = kind;
						data[1] = (uint8_t)l;
						left -= l;
						data += l;
						filled += l;
						lua_pop(L, 1);
				}
				lua_pop(L, 1);
			}
		}
end:
		while(filled & 3)
		{
			if (!left) goto err;
			*data = TCP_KIND_NOOP; data++; left--; filled++;
		}
	}

	tcp->th_off = filled>>2;
	*len = filled;

	lua_pop(L, 1);
	LUA_STACK_GUARD_LEAVE(L, 0)
	return true;
err:
	LUA_STACK_GUARD_UNWIND(L)
	return false;
}
bool lua_reconstruct_tcphdr(lua_State *L, int idx, struct tcphdr *tcp, size_t *len)
{
	if (*len<sizeof(struct tcphdr) || lua_type(L,idx)!=LUA_TTABLE) return false;

	LUA_STACK_GUARD_ENTER(L)

	idx = lua_absindex(L, idx);

	lua_getfield(L,idx,"th_sport");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_sport = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"th_dport");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_dport = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"th_seq");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_seq = htonl((uint32_t)lua_tolint(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"th_ack");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_ack = htonl((uint32_t)lua_tolint(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"th_x2");
	tcp->th_x2 = (uint8_t)lua_tointeger(L,-1);
	lua_pop(L, 1);

	lua_getfield(L,idx,"th_flags");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_flags = (uint8_t)lua_tointeger(L,-1);
	lua_pop(L, 1);

	lua_getfield(L,idx,"th_win");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_win = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"th_sum");
	tcp->th_sum = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"th_urp");
	tcp->th_urp = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	tcp->th_off = 5;

	bool b = lua_reconstruct_tcphdr_options(L, idx, tcp, len);
	LUA_STACK_GUARD_LEAVE(L, 0)
	return b;
err:
	lua_pop(L, 1);
	LUA_STACK_GUARD_LEAVE(L, 0)
	return false;
}
static int luacall_reconstruct_tcphdr(lua_State *L)
{
	lua_check_argc(L,"reconstruct_tcphdr",1);

	LUA_STACK_GUARD_ENTER(L)

	char data[60];
	size_t len=sizeof(data);
	if (!lua_reconstruct_tcphdr(L,1,(struct tcphdr*)data,&len))
		luaL_error(L, "invalid data for tcphdr");
	lua_pushlstring(L,data,len);

	LUA_STACK_GUARD_RETURN(L,1)
}

bool lua_reconstruct_udphdr(lua_State *L, int idx, struct udphdr *udp)
{
	if (lua_type(L,idx)!=LUA_TTABLE) return false;

	LUA_STACK_GUARD_ENTER(L)

	lua_getfield(L,idx,"uh_sport");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	udp->uh_sport = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"uh_dport");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	udp->uh_dport = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"uh_ulen");
	udp->uh_ulen = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"uh_sum");
	udp->uh_sum = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	LUA_STACK_GUARD_LEAVE(L, 0)
	return true;
err:
	lua_pop(L, 1);
	LUA_STACK_GUARD_LEAVE(L, 0)
	return false;
}
static int luacall_reconstruct_udphdr(lua_State *L)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_check_argc(L,"reconstruct_udphdr",1);
	struct udphdr udp;
	if (!lua_reconstruct_udphdr(L,1,&udp))
		luaL_error(L, "invalid data for udphdr");
	lua_pushlstring(L,(char*)&udp,sizeof(udp));

	LUA_STACK_GUARD_RETURN(L,1)
}

bool lua_reconstruct_icmphdr(lua_State *L, int idx, struct icmp46 *icmp)
{
	if (lua_type(L,idx)!=LUA_TTABLE) return false;

	LUA_STACK_GUARD_ENTER(L)

	lua_getfield(L,idx,"icmp_type");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	icmp->icmp_type = (uint8_t)lua_tointeger(L,-1);
	lua_pop(L, 1);

	lua_getfield(L,idx,"icmp_code");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	icmp->icmp_code = (uint8_t)lua_tointeger(L,-1);
	lua_pop(L, 1);

	lua_getfield(L,idx,"icmp_data");
	if (lua_type(L,-1)!=LUA_TNUMBER) goto err;
	icmp->data.data32 = htonl((uint32_t)lua_tolint(L,-1));
	lua_pop(L, 1);

	lua_getfield(L,idx,"icmp_cksum");
	icmp->icmp_cksum = htons((uint16_t)lua_tointeger(L,-1));
	lua_pop(L, 1);

	LUA_STACK_GUARD_LEAVE(L, 0)
	return true;
err:
	lua_pop(L, 1);
	LUA_STACK_GUARD_LEAVE(L, 0)
	return false;
}
static int luacall_reconstruct_icmphdr(lua_State *L)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_check_argc(L,"reconstruct_icmphdr",1);
	struct icmp46 icmp;
	if (!lua_reconstruct_icmphdr(L,1,&icmp))
		luaL_error(L, "invalid data for icmphdr");
	lua_pushlstring(L,(char*)&icmp,sizeof(icmp));

	LUA_STACK_GUARD_RETURN(L,1)
}

uint8_t lua_ip6_l4proto_from_dissect(lua_State *L, int idx)
{
	int type;

	lua_getfield(L,idx,"tcp");
	type=lua_type(L,-1);
	lua_pop(L,1);
	if (type==LUA_TTABLE) return IPPROTO_TCP;

	lua_getfield(L,idx,"udp");
	type=lua_type(L,-1);
	lua_pop(L,1);
	if (type==LUA_TTABLE) return IPPROTO_UDP;

	lua_getfield(L,idx,"icmp");
	type=lua_type(L,-1);
	lua_pop(L,1);
	if (type==LUA_TTABLE)
	{
		lua_getfield(L,idx,"ip");
		type=lua_type(L,-1);
		lua_pop(L,1);
		if (type==LUA_TTABLE) return IPPROTO_ICMP;

		lua_getfield(L,idx,"ip6");
		type=lua_type(L,-1);
		lua_pop(L,1);
		if (type==LUA_TTABLE) return IPPROTO_ICMPV6;
	}

	return IPPROTO_NONE;
}

// last_proto = IPPROTO_NONE means auto detect
bool lua_reconstruct_dissect(lua_State *L, int idx, uint8_t *buf, size_t *len, bool keepsum, bool badsum, uint8_t last_proto, bool ip6_preserve_next)
{
	uint8_t *data = buf;
	size_t sz,l,lpayload,l3,left = *len;
	struct ip *ip=NULL;
	struct ip6_hdr *ip6=NULL;
	struct tcphdr *tcp=NULL;
	struct udphdr *udp=NULL;
	struct icmp46 *icmp=NULL;
	const char *p;
	bool frag;

	LUA_STACK_GUARD_ENTER(L)

	idx = lua_absindex(L, idx);

	lua_getfield(L,idx,"frag_off");
	if (lua_type(L,-1)!=LUA_TNIL)
	{
		luaL_checkinteger(L,-1); // verify type
		frag = true;
	}
	else
		frag = false;
	lua_pop(L, 1);

	if (frag) ip6_preserve_next = true; // there's no other source of next. no tcp, no udp, no icmp headers. just raw ip payload

	lua_getfield(L,idx,"ip");
	l = left;
	if (lua_type(L,-1)==LUA_TTABLE)
	{
		ip = (struct ip*)data;
		if (!lua_reconstruct_iphdr(L,-1, ip, &l))
		{
			DLOG_ERR("reconstruct_dissect: bad ip\n");
			goto err;
		}
		ip4_fix_checksum(ip);
	}
	else
	{
		lua_pop(L, 1);
		lua_getfield(L,idx,"ip6");
		if (lua_type(L,-1)!=LUA_TTABLE) goto err;
		ip6 = (struct ip6_hdr*)data;
		if (!lua_reconstruct_ip6hdr(L,-1, ip6, &l, last_proto==IPPROTO_NONE ? lua_ip6_l4proto_from_dissect(L,idx) : last_proto, ip6_preserve_next))
		{
			DLOG_ERR("reconstruct_dissect: bad ip6\n");
			goto err;
		}
	}
	l3=l;
	data+=l; left-=l;
	lua_pop(L, 1);

	if (frag)
	{
		lua_getfield(L,idx,"payload");
		p = lua_tolstring(L,-1,&lpayload);
		if (p)
		{
			if (lpayload>0xFFFF)
			{
				DLOG_ERR("reconstruct_dissect: payload too large : %zu\n",lpayload);
				goto err;
			}
			if (left<lpayload)
			{
				DLOG_ERR("reconstruct_dissect: payload does not fit into the buffer : payload %zu buffer_left %zu\n",lpayload,left);
				goto err;
			}
			memcpy(data,p,lpayload);
			data+=lpayload; left-=lpayload;
		}
		else
			lpayload = 0;
		lua_pop(L, 1);
		l = data-buf;
	}
	else
	{
		lua_getfield(L,idx,"tcp");
		l=0;
		if (lua_type(L,-1)==LUA_TTABLE)
		{
			l = left;
			tcp = (struct tcphdr*)data;
			if (!lua_reconstruct_tcphdr(L, -1, tcp, &l))
			{
				DLOG_ERR("reconstruct_dissect: bad tcp\n");
				goto err;
			}
		}
		else
		{
			lua_pop(L, 1);
			lua_getfield(L,idx,"udp");
			if (lua_type(L,-1)==LUA_TTABLE)
			{
				l = sizeof(struct udphdr);
				udp = (struct udphdr*)data;
				if (!lua_reconstruct_udphdr(L, -1, udp))
				{
					DLOG_ERR("reconstruct_dissect: bad udp\n");
					goto err;
				}
			}
			else
			{
				lua_pop(L, 1);
				lua_getfield(L,idx,"icmp");
				if (lua_type(L,-1)==LUA_TTABLE)
				{
					l = sizeof(struct icmp46);
					icmp = (struct icmp46*)data;
					if (!lua_reconstruct_icmphdr(L, -1, icmp))
					{
						DLOG_ERR("reconstruct_dissect: bad icmp\n");
						goto err;
					}
				}
			}
		}
		data+=l; left-=l;
		lua_pop(L, 1);

		lua_getfield(L,idx,"payload");
		p = lua_tolstring(L,-1,&lpayload);
		if (p)
		{
			if (lpayload>0xFFFF)
			{
				DLOG_ERR("reconstruct_dissect: payload too large : %zu\n",lpayload);
				goto err;
			}
			if (left<lpayload)
			{
				DLOG_ERR("reconstruct_dissect: payload does not fit into the buffer : payload %zu buffer_left %zu\n",lpayload,left);
				goto err;
			}
			memcpy(data,p,lpayload);
			data+=lpayload; left-=lpayload;
		}
		else
			lpayload = 0;
		lua_pop(L, 1);

		l = data-buf;

		if (!keepsum)
		{
			if (tcp)
			{
				tcp_fix_checksum(tcp,l-l3,ip,ip6);
				if (badsum) tcp->th_sum ^= 1 + (random() % 0xFFFF);
			}
			else if (udp)
			{
				sz = lpayload+sizeof(struct udphdr);
				if (sz>0xFFFF)
				{
					DLOG_ERR("reconstruct_dissect: invalid payload length\n");
					goto err;
				}
				udp->uh_ulen = htons((uint16_t)sz);
				udp_fix_checksum(udp,l-l3,ip,ip6);
				if (badsum) udp->uh_sum ^= 1 + (random() % 0xFFFF);
			}
			else if (icmp)
			{
				icmp_fix_checksum(icmp,l-l3,ip6);
				if (badsum) icmp->icmp_cksum ^= 1 + (random() % 0xFFFF);
			}
		}

		if (ip)
		{
			if (ntohs(ip->ip_off) & (IP_OFFMASK|IP_MF))
			{
				// fragmentation. caller should set ip_len, ip_off and IP_MF correctly. C code moves and shrinks constructed ip payload
				uint16_t iplen = ntohs(ip->ip_len);
				uint16_t off = (ntohs(ip->ip_off) & IP_OFFMASK)<<3;
				size_t frag_start = l3 + off;
				if (iplen<l3 || iplen>l)
				{
					DLOG_ERR("ipv4 frag : invalid ip_len\n");
					goto err;
				}
				size_t frag_len = iplen-l3;
				if ((frag_start+frag_len)>l)
				{
					DLOG_ERR("ipv4 frag : fragment end is outside of the packet\n");
					goto err;
				}
				if (off) memmove(buf+l3,buf+frag_start,frag_len);
				l = iplen; // shrink packet to iplen
			}
			else
				ip->ip_len = htons((uint16_t)l);
			ip4_fix_checksum(ip);
		}
		else if (ip6)
		{
			// data points to reconstructed packet's end
			uint8_t *frag = proto_find_ip6_exthdr(ip6, l, IPPROTO_FRAGMENT);
			if (frag)
			{
				uint16_t plen = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen); // without ipv6 base header
				uint16_t off = ntohs(((struct ip6_frag *)frag)->ip6f_offlg) & 0xFFF8;
				uint8_t *endfrag = frag + 8;
				size_t size_unfragmentable = endfrag - (uint8_t*)ip6 - sizeof(struct ip6_hdr);

				if (size_unfragmentable > plen)
				{
					DLOG_ERR("ipv6 frag : invalid ip6_plen\n");
					goto err;
				}
				size_t size_fragmentable = plen - size_unfragmentable;
				if ((endfrag + off + size_fragmentable) > data)
				{
					DLOG_ERR("ipv6 frag : fragmentable part is outside of the packet\n");
					goto err;
				}
				if (off) memmove(endfrag, endfrag + off, size_fragmentable);
				l = sizeof(struct ip6_hdr) + plen;
			}
			else
				ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons((uint16_t)(l-sizeof(struct ip6_hdr)));
		}
	}

	*len = l;
	LUA_STACK_GUARD_LEAVE(L, 0)
	return true;
err:
	LUA_STACK_GUARD_UNWIND(L)
	return false;
}
static int luacall_reconstruct_dissect(lua_State *L)
{
	// reconstruct_dissect(data, reconstruct_opts)
	lua_check_argc_range(L,"reconstruct_dissect",1,2);

	LUA_STACK_GUARD_ENTER(L)

	size_t l;
	uint8_t buf[RECONSTRUCT_MAX_SIZE] __attribute__((aligned(16)));
	uint8_t last_proto;

	l = sizeof(buf);

	bool ip6_preserve_next, badsum, keepsum;
	lua_reconstruct_extract_options(L, 2, &keepsum, &badsum, &ip6_preserve_next, &last_proto);

	if (!lua_reconstruct_dissect(L, 1, buf, &l, keepsum, badsum, last_proto, ip6_preserve_next))
		luaL_error(L, "invalid dissect data");
	lua_pushlstring(L,(char*)buf,l);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_dissect(lua_State *L)
{
	// dissect(packet_data)
	lua_check_argc_range(L,"dissect",1,2);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (const uint8_t*)lua_reqlstring(L, 1, &len);
	int argc = lua_gettop(L);
	bool no_payload_check = argc>=2 ? lua_toboolean(L, 2) : false;

	struct dissect dis;
	proto_dissect_l3l4(data, len, &dis, no_payload_check);

	lua_push_dissect(L, &dis);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_csum_ip4_fix(lua_State *L)
{
	// csum_ip4_fix(ip_header) returns ip_header
	lua_check_argc(L,"csum_ip4_fix",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t l;
	const uint8_t *data = (const uint8_t*)lua_reqlstring(L, 1, &l);
	if (l>60 || !proto_check_ipv4(data, l))
		luaL_error(L, "invalid ip header");

	uint8_t data2[60];
	memcpy(data2, data, l);
	ip4_fix_checksum((struct ip*)data2);

	lua_pushlstring(L,(char*)data2,l);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_csum_tcp_fix(lua_State *L)
{
	// csum_tcp_fix(ip_header, tcp_header, payload) returns tcp_header
	lua_check_argc(L,"csum_tcp_fix",3);

	LUA_STACK_GUARD_ENTER(L)

	size_t l_ip;
	const uint8_t *b_ip = (const uint8_t*)lua_reqlstring(L, 1, &l_ip);
	const struct ip *ip=NULL;
	const struct ip6_hdr *ip6=NULL;

	if (proto_check_ipv4(b_ip, l_ip))
		ip = (struct ip*)b_ip;
	else if (proto_check_ipv6(b_ip, l_ip))
		ip6 = (struct ip6_hdr*)b_ip;
	else
		luaL_error(L, "invalid ip header");

	size_t l_tcp;
	const uint8_t *b_tcp = (const uint8_t*)lua_reqlstring(L, 2, &l_tcp);
	if (!proto_check_tcp(b_tcp, l_tcp))
		luaL_error(L, "invalid tcp header");

	size_t l_pl;
	const uint8_t *b_pl = (const uint8_t*)lua_reqlstring(L, 3, &l_pl);
	if (l_pl>0xFFFF)
		luaL_error(L, "invalid payload length");

	size_t l_tpl = l_tcp + l_pl;
	uint8_t *tpl = lua_newuserdata(L, l_tpl);

	memcpy(tpl, b_tcp, l_tcp);
	memcpy(tpl+l_tcp, b_pl, l_pl);
	struct tcphdr *tcp = (struct tcphdr*)tpl;
	tcp_fix_checksum(tcp, l_tpl, ip, ip6);

	lua_pushlstring(L,(char*)tpl,l_tcp);
	lua_remove(L,-2);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_csum_udp_fix(lua_State *L)
{
	// csum_udp_fix(ip_header, udp_header, payload) returns udp_header
	lua_check_argc(L,"csum_udp_fix",3);

	LUA_STACK_GUARD_ENTER(L)

	size_t l_ip;
	const uint8_t *b_ip = (const uint8_t*)lua_reqlstring(L, 1, &l_ip);
	const struct ip *ip=NULL;
	const struct ip6_hdr *ip6=NULL;

	if (proto_check_ipv4(b_ip, l_ip))
		ip = (struct ip*)b_ip;
	else if (proto_check_ipv6(b_ip, l_ip))
		ip6 = (struct ip6_hdr*)b_ip;
	else
		luaL_error(L, "invalid ip header");

	size_t l_udp;
	const uint8_t *b_udp = (const uint8_t*)lua_reqlstring(L, 2, &l_udp);
	if (!proto_check_udp(b_udp, l_udp))
		luaL_error(L, "invalid udp header");

	size_t l_pl;
	const uint8_t *b_pl = (const uint8_t*)lua_reqlstring(L, 3, &l_pl);
	if (l_pl>0xFFFF)
		luaL_error(L, "invalid payload length");

	size_t l_tpl = l_udp + l_pl;
	uint8_t *tpl = lua_newuserdata(L, l_tpl);

	memcpy(tpl, b_udp, l_udp);
	memcpy(tpl+l_udp, b_pl, l_pl);
	struct udphdr *udp = (struct udphdr*)tpl;
	udp_fix_checksum(udp, l_tpl, ip, ip6);

	lua_pushlstring(L,(char*)tpl,l_udp);
	lua_remove(L,-2);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_csum_icmp_fix(lua_State *L)
{
	// csum_icmp_fix(ip_header, icmp_header, payload) returns icmp_header
	lua_check_argc(L,"csum_icmp_fix",3);

	LUA_STACK_GUARD_ENTER(L)

	size_t l_ip;
	const uint8_t *b_ip = (const uint8_t*)lua_reqlstring(L, 1, &l_ip);
	const struct ip *ip=NULL;
	const struct ip6_hdr *ip6=NULL;

	if (proto_check_ipv4(b_ip, l_ip))
		ip = (struct ip*)b_ip;
	else if (proto_check_ipv6(b_ip, l_ip))
		ip6 = (struct ip6_hdr*)b_ip;
	else
		luaL_error(L, "invalid ip header");

	size_t l_icmp;
	const uint8_t *b_icmp = (const uint8_t*)lua_reqlstring(L, 2, &l_icmp);
	if (!proto_check_icmp(b_icmp, l_icmp))
		luaL_error(L, "invalid icmp header");

	size_t l_pl;
	const uint8_t *b_pl = (const uint8_t*)lua_reqlstring(L, 3, &l_pl);
	if (l_pl>0xFFFF)
		luaL_error(L, "invalid payload length");

	size_t l_tpl = l_icmp + l_pl;
	uint8_t *tpl = lua_newuserdata(L, l_tpl);

	memcpy(tpl, b_icmp, l_icmp);
	memcpy(tpl+l_icmp, b_pl, l_pl);
	struct icmp46 *icmp = (struct icmp46*)tpl;
	icmp_fix_checksum(icmp, l_tpl, ip6);

	lua_pushlstring(L,(char*)tpl,l_icmp);
	lua_remove(L,-2);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_ntop(lua_State *L)
{
	size_t l;
	const char *p;
	char s[INET6_ADDRSTRLEN];
	int af=0;

	lua_check_argc(L,"ntop",1);

	LUA_STACK_GUARD_ENTER(L)

	p=lua_reqlstring(L,1,&l);
	switch(l)
	{
		case sizeof(struct in_addr):
			af=AF_INET;
			break;
		case sizeof(struct in6_addr):
			af=AF_INET6;
			break;
		default:
			lua_pushnil(L);
			return 1;
	}
	if (inet_ntop(af,p,s,sizeof(s)))
		lua_pushstring(L,s);
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_pton(lua_State *L)
{
	const char *p;
	char s[sizeof(struct in6_addr)];

	lua_check_argc(L,"pton",1);

	LUA_STACK_GUARD_ENTER(L)

	p=lua_reqstring(L,1);
	if (inet_pton(AF_INET,p,s))
		lua_pushlstring(L,s,sizeof(struct in_addr));
	else if (inet_pton(AF_INET6,p,s))
		lua_pushlstring(L,s,sizeof(struct in6_addr));
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_RETURN(L,1)
}


static void lua_rawsend_extract_options(lua_State *L, int idx, int *repeats, uint32_t *fwmark, const char **ifout)
{
	if (lua_isnoneornil(L,idx))
	{
		if (repeats) *repeats = 1;
		if (fwmark) *fwmark = params.desync_fwmark;
		if (ifout) *ifout = NULL;
	}
	else
	{
		luaL_checktype(L, idx, LUA_TTABLE);
		if (repeats)
		{
			lua_getfield(L,idx,"repeats");
			*repeats=(int)lua_tointeger(L,-1);
			if (*repeats<0) luaL_error(L, "rawsend: negative repeats");
			if (!*repeats) *repeats=1;
			lua_pop(L,1);
		}
		if (fwmark)
		{
			lua_getfield(L,idx,"fwmark");
			*fwmark=(uint32_t)lua_tolint(L,-1) | params.desync_fwmark;
			lua_pop(L,1);
		}
		if (ifout)
		{
			lua_getfield(L,idx,"ifout");
			*ifout = lua_type(L,-1)==LUA_TSTRING ? lua_tostring(L,-1) : NULL;
			lua_pop(L,1);
		}
	}
}

static int luacall_rawsend(lua_State *L)
{
	// bool rawsend(raw_data, {repeats, fwmark, ifout})
	lua_check_argc_range(L,"rawsend",1,2);

	LUA_STACK_GUARD_ENTER(L)

	uint8_t *data;
	const char *ifout;
	size_t len;
	int repeats;
	uint32_t fwmark;
	sockaddr_in46 sa;
	bool b;

	data=(uint8_t*)lua_reqlstring(L,1,&len);
	lua_rawsend_extract_options(L,2,&repeats,&fwmark,&ifout);

	if (!extract_dst(data, len, (struct sockaddr*)&sa))
		luaL_error(L, "bad ip4/ip6 header");
	DLOG("rawsend repeats=%d size=%zu ifout=%s fwmark=%08X\n", repeats,len,ifout ? ifout : "",fwmark);

	b = rawsend_rep(repeats, (struct sockaddr*)&sa, fwmark, ifout, data, len);
	lua_pushboolean(L, b);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_rawsend_dissect(lua_State *L)
{
	// rawsend_dissect(data, rawsend_opts, reconstruct_opts)
	lua_check_argc_range(L,"rawsend_dissect",1,3);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const char *ifout;
	int repeats;
	uint32_t fwmark;
	sockaddr_in46 sa;
	bool b, badsum, keepsum, ip6_preserve_next;
	uint8_t last_proto;
	uint8_t buf[RECONSTRUCT_MAX_SIZE] __attribute__((aligned(16)));

	luaL_checktype(L,1,LUA_TTABLE);
	lua_rawsend_extract_options(L,2, &repeats, &fwmark, &ifout);
	lua_reconstruct_extract_options(L, 3, &keepsum, &badsum, &ip6_preserve_next, &last_proto);

	len = sizeof(buf);
	if (!lua_reconstruct_dissect(L, 1, buf, &len, keepsum, badsum, last_proto, ip6_preserve_next))
		luaL_error(L, "invalid dissect data");

	if (!extract_dst(buf, len, (struct sockaddr*)&sa))
		luaL_error(L, "bad ip4/ip6 header");
	DLOG("rawsend_dissect repeats=%d size=%zu badsum=%u ifout=%s fwmark=%08X\n", repeats,len,badsum,ifout ? ifout : "",fwmark);
	b = rawsend_rep(repeats, (struct sockaddr*)&sa, fwmark, ifout, buf, len);
	lua_pushboolean(L, b);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_conntrack_feed(lua_State *L)
{
	// conntrack_feed(dissect/raw_packet[, reconstruct_opts]) return track,bOutgoing
	lua_check_argc_range(L,"conntrack_feed",1,3);

	LUA_STACK_GUARD_ENTER(L)

	if (params.ctrack_disable)
		goto err;
	else
	{
		size_t len;
		bool badsum, keepsum, ip6_preserve_next, bReverse;
		uint8_t last_proto;
		struct dissect dis;
		t_ctrack *ctrack;
		const uint8_t *pbuf;
		uint8_t buf[RECONSTRUCT_MAX_SIZE] __attribute__((aligned(16)));

		switch(lua_type(L,1))
		{
			case LUA_TTABLE:
				lua_reconstruct_extract_options(L, 2, &keepsum, &badsum, &ip6_preserve_next, &last_proto);
				len = sizeof(buf);
				if (!lua_reconstruct_dissect(L, 1, buf, &len, keepsum, badsum, last_proto, ip6_preserve_next))
					luaL_error(L, "invalid dissect data");
				pbuf = buf;
				break;
			case LUA_TSTRING:
				pbuf = (const uint8_t*)lua_tolstring(L,1,&len);
				break;
			default:
				luaL_error(L, "invalid packet data type");
		}

		proto_dissect_l3l4(pbuf, len, &dis, false);

		ConntrackPoolPurge(&params.conntrack);
		if (ConntrackPoolFeed(&params.conntrack, &dis, &ctrack, &bReverse))
		{
			lua_push_ctrack(L, ctrack, NULL, bReverse);
			lua_pushboolean(L, !bReverse); // outgoing
		}
		else
			goto err;
	}

ex:
	LUA_STACK_GUARD_RETURN(L,2)
err:
	lua_pushnil(L);
	lua_pushnil(L);
	goto ex;
}

static int luacall_get_source_ip(lua_State *L)
{
	// get_source_ip(target_ip)
	lua_check_argc(L,"get_source_ip",1);

	LUA_STACK_GUARD_ENTER(L)

	union
	{
		struct in_addr a4;
		struct in6_addr a6;
	} a;
	size_t len;
	const uint8_t *data = (uint8_t*)lua_reqlstring(L,1,&len);

	switch(len)
	{
		case sizeof(struct in_addr) :
			if (get_source_ip4((struct in_addr*)data, &a.a4))
				lua_pushlstring(L,(char*)&a.a4,sizeof(a.a4));
			else
				lua_pushnil(L);
			break;
		case sizeof(struct in6_addr) :
			if (get_source_ip6((struct in6_addr*)data, &a.a6))
				lua_pushlstring(L,(char*)&a.a6,sizeof(a.a6));
			else
				lua_pushnil(L);
			break;
		default:
			luaL_error(L, "invalid IP length %u", (unsigned int)len);
	}

	LUA_STACK_GUARD_RETURN(L,1)
}

#ifdef __CYGWIN__
#define GAA_FLAGS (GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST)
static int lua_get_ifaddrs(lua_State *L)
{
	LUA_STACK_GUARD_ENTER(L)

	ULONG Size=0;
	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, NULL, NULL, &Size)==ERROR_BUFFER_OVERFLOW)
	{
		PIP_ADAPTER_ADDRESSES pip, pips = (PIP_ADAPTER_ADDRESSES)lua_newuserdata(L, Size);
		if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, NULL, pips, &Size)==ERROR_SUCCESS)
		{
			lua_newtable(L);
			for(pip=pips; pip ; pip=pip->Next)
			{
				if (!pip->FirstUnicastAddress || pip->OperStatus!=IfOperStatusUp) continue; // disconnected ?

				char ifname[16];
				snprintf(ifname,sizeof(ifname),"%u.0",pip->IfIndex);
				lua_pushf_table(L,ifname);
				lua_getfield(L,-1,ifname);
				lua_pushf_str(L, "guid", pip->AdapterName);
				if (pip->PhysicalAddressLength) lua_pushf_lstr(L, "phys",  pip->PhysicalAddress, pip->PhysicalAddressLength);
				lua_pushf_int(L, "index", pip->IfIndex);
				lua_pushf_int(L, "index6", pip->Ipv6IfIndex);
				lua_pushf_int(L, "flags", pip->Flags);
				lua_pushf_lint(L, "mtu", pip->Mtu);
				lua_pushf_int(L, "iftype", pip->IfType);
				lua_pushf_lint(L, "speed_xmit", pip->TransmitLinkSpeed);
				lua_pushf_lint(L, "speed_recv", pip->ReceiveLinkSpeed);
				lua_pushf_lint(L, "metric4", pip->Ipv4Metric);
				lua_pushf_lint(L, "metric6", pip->Ipv6Metric);
				lua_pushf_lint(L, "conntype", pip->ConnectionType);
				lua_pushf_lint(L, "tunneltype", pip->TunnelType);
				lua_pushf_table(L,"addr");
				lua_getfield(L,-1,"addr");

				int n;
				uint32_t a4,a44;
				PIP_ADAPTER_UNICAST_ADDRESS_LH pa;
				for(pa=pip->FirstUnicastAddress, n=1; pa ; pa=pa->Next, n++)
				{
					lua_pushi_table(L, n);
					lua_rawgeti(L, -1, n);
					lua_pushf_ipaddr(L, "addr", pa->Address.lpSockaddr);
					switch(pa->Address.lpSockaddr->sa_family)
					{
						case AF_INET:
							if (pa->OnLinkPrefixLength<=32)
							{
								a44 = mask_from_bitcount(pa->OnLinkPrefixLength);
								a4 = ~a44;
								lua_pushf_lstr(L, "netmask", (const char*)&a4, 4);
								a4 &= ((struct sockaddr_in*)pa->Address.lpSockaddr)->sin_addr.s_addr;
								a4 |= a44;
								lua_pushf_lstr(L, "broadcast", (const char*)&a4, 4);
							}
							break;
						case AF_INET6:
							if (pa->OnLinkPrefixLength<=128)
							{
								lua_pushf_lstr(L, "netmask", (const char*)mask_from_bitcount6(128 - pa->OnLinkPrefixLength), 16);
							}
							break;
					}
					lua_pushf_ipaddr(L, "addr", pa->Address.lpSockaddr);
					lua_pop(L,1);
				}
				lua_pop(L,2);
			}
			lua_remove(L,-2);
			goto ok;
		}
		lua_remove(L,-1);
	}

	lua_pushnil(L);

ok:
	LUA_STACK_GUARD_RETURN(L,1)
}
#else
// in cygwin this does not work with low intergity level because of cygwin objects in NT directory tree
static int lua_get_ifaddrs(lua_State *L)
{
	LUA_STACK_GUARD_ENTER(L)

	struct ifaddrs *addrs,*a;
	unsigned int index;
	lua_Integer li;
	struct ifreq ifr;
	const char *ifname;
#ifdef __CYGWIN__
	char ifname_buf[IFNAMSIZ];
#endif
	memset(&ifr,0,sizeof(ifr));

	if (getifaddrs(&addrs)<0)
		lua_pushnil(L);
	else
	{
		int sock = socket(AF_INET,SOCK_DGRAM,0);
		lua_newtable(L);
		a  = addrs;
		for(a=addrs ; a ; a=a->ifa_next)
		{
			if (a->ifa_addr && (a->ifa_addr->sa_family==AF_INET || a->ifa_addr->sa_family==AF_INET6) && a->ifa_name && *a->ifa_name)
			{
#ifdef __CYGWIN__
				// cygwin returns GUID interface names. windivert needs ifindex.subindex
				if (index = if_nametoindex(a->ifa_name))
				{
					snprintf(ifname_buf,sizeof(ifname_buf),"%u.0",index);
					ifname = ifname_buf;
				}
#else
				ifname = a->ifa_name;
#endif
				lua_getfield(L,-1,ifname);
				if (lua_isnil(L,-1))
				{
					lua_pop(L,1);
					lua_pushf_table(L,ifname);
					lua_getfield(L,-1,ifname);
#ifdef __CYGWIN__
					lua_pushf_str(L, "guid", a->ifa_name);
#else
					index = if_nametoindex(ifname);
#endif
					if (index) lua_pushf_int(L, "index", index);
					lua_pushf_int(L, "flags", a->ifa_flags);
#ifdef HAS_FILTER_SSID
					lua_pushf_str(L, "ssid", wlan_ssid_search_ifname(ifname));
#endif
					memset(ifr.ifr_name,0,sizeof(ifr.ifr_name));
					strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
					if (sock>=0 && !ioctl(sock, SIOCGIFMTU, &ifr))
						lua_pushf_int(L, "mtu", ifr.ifr_mtu);

					lua_pushf_table(L,"addr");
				}
				lua_getfield(L,-1,"addr");
				li = lua_rawlen(L,-1)+1;
				lua_pushi_table(L, li);
				lua_rawgeti(L,-1,li);
				lua_pushf_ipaddr(L, "addr", a->ifa_addr);
				lua_pushf_ipaddr(L, "netmask", a->ifa_netmask);
				lua_pushf_ipaddr(L, "broadcast", a->ifa_broadaddr);
				lua_pushf_ipaddr(L, "dst", a->ifa_dstaddr);
				lua_pop(L,3);
			}
		}
		freeifaddrs(addrs);
		if (sock>=0) close(sock);
	}

	LUA_STACK_GUARD_RETURN(L,1)
}
#endif // CYGWIN

static int luacall_get_ifaddrs(lua_State *L)
{
	lua_check_argc(L,"get_ifaddrs",0);
	lua_get_ifaddrs(L);
	return 1;
}

static int luacall_resolve_pos(lua_State *L)
{
	// resolve_pos(blob,l7payload_type,marker[,zero_based_pos])
	lua_check_argc_range(L,"resolve_pos",3,4);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t len;
	const uint8_t *data = (uint8_t*)lua_reqlstring(L,1,&len);
	const char *sl7payload = lua_reqstring(L,2);
	const char *smarker = lua_reqstring(L,3);
	bool bZeroBased = argc>=4 && lua_toboolean(L,4);

	t_l7payload l7payload = l7payload_from_name(sl7payload);
	if (l7payload==L7P_INVALID)
		luaL_error(L, "bad payload type : '%s'", sl7payload);

	struct proto_pos marker;
	if (!posmarker_parse(smarker,&marker))
		luaL_error(L, "bad marker : '%s'", smarker);
	ssize_t pos=ResolvePos(data, len, l7payload, &marker);

	if (pos==POS_NOT_FOUND)
		lua_pushnil(L);
	else
		lua_pushinteger(L,pos+!bZeroBased);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_resolve_multi_pos(lua_State *L)
{
	// resolve_multi_pos(blob,l7payload_type,marker_list[,zero_based_pos])
	lua_check_argc_range(L,"resolve_multi_pos",3,4);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t len;
	const uint8_t *data = (uint8_t*)lua_reqlstring(L,1,&len);
	const char *sl7payload = lua_reqstring(L,2);
	const char *smarkers = lua_reqstring(L,3);
	bool bZeroBased = argc>=4 && lua_toboolean(L,4);

	t_l7payload l7payload = l7payload_from_name(sl7payload);
	if (l7payload==L7P_INVALID)
		luaL_error(L, "bad payload type : '%s'", sl7payload);

	struct proto_pos markers[128];
	ssize_t pos[sizeof(markers)/sizeof(*markers)];
	int i, ctpos, ctm = sizeof(markers)/sizeof(*markers);
	if (!posmarker_list_parse(smarkers,markers,&ctm))
		luaL_error(L, "bad marker list");
	ResolveMultiPos(data, len, l7payload, markers, ctm, pos, &ctpos);

	lua_newtable(L);
	for(i=0;i<ctpos;i++) lua_pushi_int(L,i+1,pos[i]+!bZeroBased);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_resolve_range(lua_State *L)
{
	// resolve_range(blob,l7payload_type,marker_list[,strict][,zero_based_pos])
	// "strict" means do not expand range to the beginning/end if only one pos is resolved
	lua_check_argc_range(L,"resolve_range",3,5);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t i,len;
	const uint8_t *data = (uint8_t*)lua_reqlstring(L,1,&len);
	const char *sl7payload = lua_reqstring(L,2);
	const char *smarkers = lua_reqstring(L,3);
	bool bStrict = argc>=4 && lua_toboolean(L,4);
	bool bZeroBased = argc>=5 && lua_toboolean(L,5);

	t_l7payload l7payload = l7payload_from_name(sl7payload);
	if (l7payload==L7P_INVALID)
		luaL_error(L, "bad payload type : '%s'", sl7payload);

	struct proto_pos markers[2];
	ssize_t pos[sizeof(markers)/sizeof(*markers)];
	int ctm = sizeof(markers)/sizeof(*markers);
	if (!posmarker_list_parse(smarkers,markers,&ctm))
		luaL_error(L, "bad marker list");
	if (ctm!=2)
		luaL_error(L, "resolve_range require 2 markers");
	pos[0] = ResolvePos(data, len, l7payload, markers);
	pos[1] = ResolvePos(data, len, l7payload, markers+1);
	if (pos[0]==POS_NOT_FOUND && pos[1]==POS_NOT_FOUND || bStrict && (pos[0]==POS_NOT_FOUND || pos[1]==POS_NOT_FOUND))
	{
		lua_pushnil(L);
		return 1;
	}
	if (pos[0]==POS_NOT_FOUND) pos[0] = 0;
	if (pos[1]==POS_NOT_FOUND) pos[1] = len-1;
	if (pos[0]>pos[1])
	{
		lua_pushnil(L);
		return 1;
	}

	lua_newtable(L);
	lua_pushi_int(L,1,pos[0]+!bZeroBased);
	lua_pushi_int(L,2,pos[1]+!bZeroBased);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_tls_mod(lua_State *L)
{
	// (blob, modlist, payload)
	lua_check_argc_range(L,"tls_mod",2,3);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);

	size_t fake_tls_len;
	const uint8_t *fake_tls = (uint8_t*)lua_reqlstring(L,1,&fake_tls_len);
	const char *modlist = lua_reqstring(L,2);

	size_t payload_len = 0;
	const uint8_t *payload = NULL;
	if (argc>=3 && lua_type(L,3)!=LUA_TNIL)
		payload = (uint8_t*)lua_reqlstring(L,3,&payload_len);

	struct fake_tls_mod mod;
	if (!TLSMod_parse_list(modlist, &mod))
		luaL_error(L, "invalid tls mod list : '%s'", modlist);

	if (mod.mod)
	{
		size_t newlen = fake_tls_len, maxlen = fake_tls_len + sizeof(mod.sni) + 4;

		uint8_t *newtls = lua_newuserdata(L, maxlen);

		memcpy(newtls, fake_tls, newlen);
		if (TLSMod(&mod, payload, payload_len, newtls, &newlen, maxlen))
			lua_pushlstring(L,(char*)newtls,newlen);
		else
			lua_pushnil(L);

		lua_remove(L,-2);
	}
	else
	{
		// no mod. push it back
		lua_pushlstring(L,(char*)fake_tls,fake_tls_len);
	}

	LUA_STACK_GUARD_RETURN(L,1)
}

struct userdata_zs
{
	bool valid, inflate;
	z_stream zs;
};
static int lua_cfunc_zstream_gc(lua_State *L)
{
	struct userdata_zs *uzs = (struct userdata_zs *)luaL_checkudata(L, 1, "userdata_zstream");
	if (uzs->valid)
	{
		if (uzs->inflate)
			inflateEnd(&uzs->zs);
		else
			deflateEnd(&uzs->zs);
		uzs->valid = false;
	}
	return 0;
}
static void lua_mt_init_zstream(lua_State *L)
{
	LUA_STACK_GUARD_ENTER(L)

	luaL_newmetatable(L, "userdata_zstream");
	lua_pushcfunction(L, lua_cfunc_zstream_gc);
	lua_setfield(L, -2, "__gc");
	// Lua 5.5+ to-be-closed var
	lua_pushcfunction(L, lua_cfunc_zstream_gc);
	lua_setfield(L, -2, "__close");
	lua_pop(L,1);

	LUA_STACK_GUARD_LEAVE(L, 0)
}
static struct userdata_zs *lua_uzs(lua_State *L, int idx, bool bInflate)
{
	struct userdata_zs *uzs = (struct userdata_zs *)luaL_checkudata(L, idx, "userdata_zstream");
	if (!uzs->valid) luaL_error(L, "gzip stream is not valid");
	if (bInflate!=uzs->inflate) luaL_error(L, "gzip stream role mismatch");
	return uzs;
}
static int luacall_gunzip_init(lua_State *L)
{
	// gunzip_init(windowBits) return zstream
	lua_check_argc_range(L,"gunzip_init",0,1);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	int windowBits = (argc>=1 && !lua_isnil(L,1)) ? luaL_checkinteger(L, 1) : 47;

	struct userdata_zs *uzs = (struct userdata_zs *)lua_newuserdata(L, sizeof(struct userdata_zs));
	memset(&uzs->zs, 0, sizeof(uzs->zs));
	int r = inflateInit2(&uzs->zs, windowBits);
	if (r == Z_OK)
	{
		uzs->inflate = true;
		uzs->valid = true;
		luaL_getmetatable(L, "userdata_zstream");
		lua_setmetatable(L, -2);
	}
	else
	{
		lua_pop(L,1);
		lua_pushnil(L);
	}

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_gunzip_end(lua_State *L)
{
	lua_check_argc(L,"gunzip_end",1);

	LUA_STACK_GUARD_ENTER(L)

	struct userdata_zs *uzs = lua_uzs(L, 1, true);
	inflateEnd(&uzs->zs);
	uzs->valid = false;

	LUA_STACK_GUARD_RETURN(L,0)
}
#define BUFMIN 64
#define Z_INFL_BUF_INCREMENT	16384
#define Z_DEFL_BUF_INCREMENT	8192
static int luacall_gunzip_inflate(lua_State *L)
{
	// gunzip_inflate(zstream, compressed_data, expected_uncompressed_chunk_size) return decompressed_data
	lua_check_argc_range(L,"gunzip_inflate",2,3);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t l;
	int r;
	size_t bufsize=0, size=0;
	uint8_t *buf=NULL, *newbuf;
	struct userdata_zs *uzs = lua_uzs(L, 1, true);
	uzs->zs.next_in = (z_const Bytef*)luaL_checklstring(L,2,&l);
	uzs->zs.avail_in = (uInt)l;
	size_t bufchunk = argc>=3 ? luaL_checkinteger(L,3) : l*4;
	size_t increment = bufchunk / 2;
	if (increment < Z_INFL_BUF_INCREMENT) increment = Z_INFL_BUF_INCREMENT;

	for(;;)
	{
		if ((bufsize - size) < BUFMIN)
		{
			if (buf)
			{
				bufsize += increment;
				newbuf = realloc(buf, bufsize);
			}
			else
			{
				bufsize += bufchunk;
				newbuf = malloc(bufsize);
			}
			if (!newbuf)
			{
				r = Z_MEM_ERROR;
				goto zerr;
			}
			buf = newbuf;
		}
		uzs->zs.avail_out = bufsize - size;
		uzs->zs.next_out = buf + size;

		r = inflate(&uzs->zs, Z_NO_FLUSH);

		size = bufsize - uzs->zs.avail_out;
		if (r==Z_STREAM_END) break;
		if (r==Z_BUF_ERROR)
		{
			if (uzs->zs.avail_in)
				goto zerr;
			else
				break; // OK
		}
		if (r!=Z_OK) goto zerr;
	}
	lua_pushlstring(L, (const char*)buf, size);
	lua_pushboolean(L, r==Z_STREAM_END);
end:
	free(buf);
	LUA_STACK_GUARD_RETURN(L,2)
zerr:
	lua_pushnil(L);
	lua_pushnil(L);
	goto end;
}

static void *z_alloc(voidpf opaque, uInt items, uInt size)
{
	return malloc((size_t)items*size);
}
static void z_free(voidpf opaque, voidpf address)
{
	free(address);
}
static int luacall_gzip_init(lua_State *L)
{
	// gzip_init(windowBits, level, memlevel) return zstream
	lua_check_argc_range(L,"gzip_init",0,3);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	int windowBits = (argc>=1 && !lua_isnil(L,1)) ? luaL_checkinteger(L, 1) : 31;
	int level = (argc>=2 && !lua_isnil(L,2)) ? luaL_checkinteger(L, 2) : 9;
	int memlevel = (argc>=3 && !lua_isnil(L,3)) ? luaL_checkinteger(L, 3) : 8;

	struct userdata_zs *uzs = (struct userdata_zs *)lua_newuserdata(L, sizeof(struct userdata_zs));
	memset(&uzs->zs, 0, sizeof(uzs->zs));
	uzs->zs.zalloc = z_alloc;
	uzs->zs.zfree = z_free;
	int r = deflateInit2(&uzs->zs, level, Z_DEFLATED, windowBits, memlevel, Z_DEFAULT_STRATEGY);
	if (r == Z_OK)
	{
		uzs->inflate = false;
		uzs->valid = true;
		luaL_newmetatable(L, "userdata_zstream");
		lua_setmetatable(L, -2);
	}
	else
	{
		lua_pop(L,1);
		lua_pushnil(L);
	}

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_gzip_end(lua_State *L)
{
	lua_check_argc(L,"gzip_end",1);

	LUA_STACK_GUARD_ENTER(L)

	struct userdata_zs *uzs = lua_uzs(L, 1, false);
	deflateEnd(&uzs->zs);
	uzs->valid = false;

	LUA_STACK_GUARD_RETURN(L,0)
}

static int luacall_gzip_deflate(lua_State *L)
{
	// gzip_deflate(zstream, decompressed_data, expected_compressed_chunk_size) return compressed_data
	lua_check_argc_range(L,"gzip_deflate",1,3);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t l=0;
	int r, flush;
	size_t bufsize=0, size=0;
	uint8_t *buf=NULL, *newbuf;
	struct userdata_zs *uzs = lua_uzs(L, 1, false);
	if (argc>=2 && !lua_isnil(L,2))
	{
		uzs->zs.next_in = (z_const Bytef*)luaL_checklstring(L,2,&l);
		uzs->zs.avail_in = (uInt)l;
	}
	size_t bufchunk = BUFMIN + (argc>=3 ? luaL_checkinteger(L,3) : l/2);
	size_t increment = bufchunk / 2;
	if (increment < Z_DEFL_BUF_INCREMENT) increment = Z_DEFL_BUF_INCREMENT;

	flush = l ? Z_NO_FLUSH : Z_FINISH;
	for(;;)
	{
		if ((bufsize - size) < BUFMIN)
		{
			if (buf)
			{
				bufsize += increment;
				newbuf = realloc(buf, bufsize);
			}
			else
			{
				bufsize += bufchunk;
				newbuf = malloc(bufsize);
			}
			if (!newbuf)
			{
				r = Z_MEM_ERROR;
				goto zerr;
			}
			buf = newbuf;
		}
		uzs->zs.avail_out = bufsize - size;
		uzs->zs.next_out = buf + size;

		r = deflate(&uzs->zs, flush);

		size = bufsize - uzs->zs.avail_out;
		if (r==Z_STREAM_END) break;
		if (r==Z_OK)
		{
			if (uzs->zs.avail_out && !uzs->zs.avail_in && flush != Z_FINISH)
				 break;
		}
		else
			goto zerr;
	}

	lua_pushlstring(L, (const char*)buf, size);
	lua_pushboolean(L, r==Z_STREAM_END);
end:
	free(buf);
	LUA_STACK_GUARD_RETURN(L,2)
zerr:
	lua_pushnil(L);
	lua_pushnil(L);
	goto end;
}


static int luacall_stat(lua_State *L)
{
	// stat(filename) return stat_table or nil,strerror,errno
	lua_check_argc(L,"stat",1);

	int n=1;
	struct stat st;
	if (stat(luaL_checkstring(L,1), &st))
	{
		lua_pushnil(L);
		const char *err = strerror(errno);
		if (err)
		{
			lua_pushstring(L,err);
			lua_pushinteger(L,errno);
			return 3;
		}
	}
	else
	{
		lua_createtable(L, 0, 5);
		lua_pushf_lint(L,"dev", st.st_dev);
		lua_pushf_lint(L,"inode", st.st_ino);
		lua_pushf_lint(L,"size", st.st_size);
#ifdef __APPLE__
		lua_pushf_number(L,"mtime", st.st_mtimespec.tv_sec + st.st_mtimespec.tv_nsec/1000000000.);
#else
		lua_pushf_number(L,"mtime", st.st_mtim.tv_sec + st.st_mtim.tv_nsec/1000000000.);
#endif

		const char *ftype;
		switch(st.st_mode & S_IFMT)
		{
			case S_IFREG: ftype="file"; break;
			case S_IFDIR: ftype="dir"; break;
			case S_IFLNK: ftype="symlink"; break;
			case S_IFSOCK: ftype="socket"; break;
			case S_IFBLK: ftype="blockdev"; break;
			case S_IFCHR: ftype="chardev"; break;
			case S_IFIFO: ftype="fifo"; break;
			default: ftype="unknown"; break;
		}

		lua_pushf_str(L, "type", ftype);
	}
	return 1;
}

static void lua_xtime(lua_State *L, struct tm *(*timefunc)(const time_t *,struct tm *))
{
	struct tm t;

	time_t unixtime = (time_t)luaL_checklint(L,1);
	if (!timefunc(&unixtime, &t))
	{
		lua_pushnil(L);
	}
	else
	{
		lua_createtable(L, 0, 11);
		lua_pushf_int(L,"sec", t.tm_sec);
		lua_pushf_int(L,"min", t.tm_min);
		lua_pushf_int(L,"hour", t.tm_hour);
		lua_pushf_int(L,"mday", t.tm_mday);
		lua_pushf_int(L,"mon", t.tm_mon);
		lua_pushf_int(L,"year", t.tm_year+1900);
		lua_pushf_int(L,"wday", t.tm_wday);
		lua_pushf_int(L,"yday", t.tm_yday);
		lua_pushf_int(L,"isdst", t.tm_isdst);
		lua_pushf_str(L,"zone", t.tm_zone);

		char s[40];
		snprintf(s,sizeof(s),"%02d.%02d.%04d %02d:%02d:%02d", t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, t.tm_hour, t.tm_min, t.tm_sec);
		lua_pushf_str(L,"str", s);
	}
}
static int luacall_localtime(lua_State *L)
{
	// localtime(unixtime)
	lua_check_argc(L,"localtime",1);
	lua_xtime(L, localtime_r);
	return 1;
}
static int luacall_gmtime(lua_State *L)
{
	// gmtime(unixtime)
	lua_check_argc(L,"gmtime",1);
	lua_xtime(L, gmtime_r);
	return 1;
}
#define TIMEX_VAL(v) \
	lua_getfield(L,1,#v); \
	if (lua_type(L,-1)!=LUA_TNUMBER) luaL_error(L,"invalid tm." #v); \
	t.tm_##v = lua_tointeger(L,-1); \
	lua_pop(L,1);
static void lua_timex(lua_State *L, time_t (*timefunc)(struct tm *))
{
	if (lua_type(L,1)!=LUA_TTABLE) luaL_error(L,"invalid tm structure");

	struct tm t;
	TIMEX_VAL(sec)
	TIMEX_VAL(min)
	TIMEX_VAL(hour)
	TIMEX_VAL(mday)
	TIMEX_VAL(mon)
	TIMEX_VAL(year)
	t.tm_year-=1900;
	TIMEX_VAL(isdst)

	time_t unixtime = timefunc(&t);
	if (unixtime==(time_t)-1)
	{
		lua_pushnil(L);
	}
	else
		lua_pushlint(L,unixtime);
}
static int luacall_timelocal(lua_State *L)
{
	// timelocal(tm)
	lua_check_argc(L,"timelocal",1);
	lua_timex(L, mktime);
	return 1;
}
static int luacall_timegm(lua_State *L)
{
	// timegm(tm)
	lua_check_argc(L,"timegm",1);
	lua_timex(L, timegm);
	return 1;
}

static int luacall_timer_set(lua_State *L)
{
	// timer_set(name, func, period, oneshot, data)
	lua_check_argc_range(L,"timer_set",3,5);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	const char *name =  luaL_checkstring(L,1);
	const char *func =  luaL_checkstring(L,2);
	lua_Integer period = luaL_checkinteger(L,3);
	if (period<10) luaL_error(L,"invalid timer period. must be >=10 ms");
	bool oneshot = argc>=4 && lua_toboolean(L,4);

	lua_getglobal(L, func);
	bool is_f = lua_isfunction(L, -1);
	lua_pop(L, 1);
	if (!is_f) luaL_error(L, "timer function '%s' does not exist", func);

	const char *action;
	timer_pool *timer = TimerPoolSearch(params.timers, name);
	if (timer)
	{
		TimerPoolDel(&params.timers, timer);
		action = "replaced";
	}
	else
		action = "created";

	timer = TimerPoolAdd(&params.timers, name, func, period, oneshot);
	if (!timer) luaL_error(L,"could not create timer");

	if (argc>=5)
	{
		lua_pushvalue(L, 5);
		timer->lua_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	}
	DLOG("timer: '%s' %s. function '%s' period %llu oneshot %u\n", timer->str, action, timer->func, timer->period, timer->oneshot);
	params.timers_dirty = true;

	LUA_STACK_GUARD_RETURN(L,0)
}
static int luacall_timer_del(lua_State *L)
{
	// timer_del(name)
	lua_check_argc(L,"timer_del",1);

	LUA_STACK_GUARD_ENTER(L)

	const char *name =  luaL_checkstring(L,1);
	timer_pool *timer = TimerPoolSearch(params.timers, name);
	if (timer)
	{
		DLOG("timer: '%s' deleted\n", timer->str);
		TimerPoolDel(&params.timers, timer);
		params.timers_dirty = true;
	}
	else
		DLOG("timer: '%s' not found\n", name);
	lua_pushboolean(L, !!timer);
	LUA_STACK_GUARD_RETURN(L,1)
}
static void lua_push_timer_info(lua_State *L, const timer_pool *timer)
{
	lua_newtable(L);
	if (timer->str) lua_pushf_str(L, "name", timer->str);
	if (timer->func) lua_pushf_str(L, "func", timer->func);
	lua_pushf_lint(L, "period", timer->period);
	lua_pushf_bool(L, "oneshot", timer->oneshot);
	lua_pushf_lint(L, "fires", timer->fires);
}
static int luacall_timer_info(lua_State *L)
{
	// timer_info(name)
	lua_check_argc(L,"timer_info",1);

	LUA_STACK_GUARD_ENTER(L)

	const char *name =  luaL_checkstring(L,1);
	const timer_pool *timer = TimerPoolSearch(params.timers, name);
	if (timer)
		lua_push_timer_info(L, timer);
	else
		lua_pushnil(L);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_timer_enum(lua_State *L)
{
	// timer_enum()
	lua_check_argc(L,"timer_enum",0);

	LUA_STACK_GUARD_ENTER(L)

	lua_Integer n=1;
	timer_pool *timer, *tmp, *p;

	lua_newtable(L);
	HASH_ITER(hh, params.timers, timer, tmp) lua_pushi_str(L, n++, timer->str);

	LUA_STACK_GUARD_RETURN(L,1)
}


// ----------------------------------------

void lua_cleanup(lua_State *L)
{
	lua_desync_ctx_destroy(L);
	// conntrack holds lua state. must clear it before lua shoudown
	ConntrackPoolDestroy(&params.conntrack);
	// timer can hold custom lua object
	TimerPoolDestroy(&params.timers);
}

void lua_shutdown()
{
	if (params.L)
	{
		DLOG("LUA SHUTDOWN\n");
		lua_cleanup(params.L);
		lua_close(params.L);
		params.L=NULL;
	}
}

#if LUA_VERSION_NUM >= 504
static void lua_warn(void *ud, const char *msg, int tocont)
{
	DLOG_CONDUP("LUA WARNING: %s\n",msg);
}
#endif
static void lua_perror(lua_State *L)
{
	if (lua_isstring(L, -1))
	{
		const char *error_message = lua_tostring(L, -1);
		DLOG_ERR("LUA ERROR: %s\n", error_message);
	}
	lua_pop(L, 1);
}
static int lua_panic(lua_State *L)
{
	lua_perror(L);
	DLOG_ERR("LUA PANIC: THIS IS FATAL. DYING.\n");
	exit(100);
	return 0;
}

static bool lua_basic_init()
{
	lua_shutdown();
	if (!(params.L = luaL_newstate()))
	{
		DLOG_ERR("LUA INIT ERROR\n");
		return false;
	}
	unsigned int ver;
#if LUA_VERSION_NUM >= 504
	ver = (unsigned int)lua_version(params.L);
#elif LUA_VERSION_NUM >= 502
	ver = (unsigned int)*lua_version(params.L);
#else
	ver = LUA_VERSION_NUM;
#endif
#ifdef LUAJIT_VERSION
#ifdef OPENRESTY_LUAJIT
#define LJSUBVER " OpenResty"
#else
#define LJSUBVER ""
#endif
	DLOG_CONDUP("LUA v%u.%u %s%s\n",ver/100,ver%100, LUAJIT_VERSION, LJSUBVER);
#else
	DLOG_CONDUP("LUA v%u.%u\n",ver/100,ver%100);
#endif

#if LUA_VERSION_NUM >= 504
	lua_setwarnf(params.L,lua_warn,NULL);
#endif
	lua_atpanic(params.L,lua_panic);
	luaL_openlibs(params.L); /* Load Lua libraries */

	lua_getfield(params.L, LUA_REGISTRYINDEX, "_LOADED");
	if (lua_type(params.L, -1)==LUA_TTABLE)
	{
		lua_getfield(params.L, -1, "jit");
		if (lua_type(params.L, -1)==LUA_TTABLE)
		{
			lua_getfield(params.L, -1, "status");
			if (lua_type(params.L, -1)==LUA_TFUNCTION)
			{
				const char *s;
				int n = lua_gettop(params.L);

				lua_call(params.L, 0, LUA_MULTRET);
				DLOG_CONDUP(lua_toboolean(params.L, n) ? "JIT: ON" : "JIT: OFF");
				for (n++; (s = lua_tostring(params.L, n)); n++)
					DLOG_CONDUP(" %s", s);
				DLOG_CONDUP("\n");
			}
		}
	}
	lua_settop(params.L, 0);

	return true;
}

static bool lua_desync_functions_exist()
{
	struct desync_profile_list *dpl;
	struct func_list *func;

	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		LIST_FOREACH(func, &dpl->dp.lua_desync, next)
		{
			lua_getglobal(params.L, func->func);
			if (!lua_isfunction(params.L,-1))
			{
				lua_pop(params.L,1);
				DLOG_ERR("desync function '%s' does not exist\n",func->func);
				return false;
			}
			lua_pop(params.L,1);
		}
	}
	return true;
}

static bool lua_file_open_test(const char *filename, bool *b_gzip, char *fname)
{
	FILE *F = fopen(filename,"rb");
	if (F)
	{
		if (fname) snprintf(fname,PATH_MAX,"%s",filename);
	}
	else
	{
		size_t l = strlen(filename);
		char *fngz = malloc(l+4);
		if (!fngz) return false;
		memcpy(fngz, filename, l);
		memcpy(fngz+l,".gz",4);
		if (fname) snprintf(fname,PATH_MAX,"%s",fngz);
		F = fopen(fngz,"rb");
		free(fngz);
	}
	if (F)
	{
		if (b_gzip) *b_gzip = is_gzip(F);
		fclose(F);
	}
	return F;
}

bool lua_test_init_script_files(void)
{
	struct str_list *str;
	LIST_FOREACH(str, &params.lua_init_scripts, next)
	{
		if (str->str[0]=='@' && !lua_file_open_test(str->str+1, NULL, NULL))
		{
#ifndef __CYGWIN__
			int e = errno;
#endif
			DLOG_ERR("LUA file '%s' or '%s.gz' not accessible\n", str->str+1, str->str+1);
#ifndef __CYGWIN__
			if (e==EACCES)
				DLOG_ERR("I drop my privileges and do not run Lua as root\ncheck file permissions and +x rights on all directories in the path\n");
#endif
			return false;
		}
	}
	return true;
}

static int luaL_doZfile(lua_State *L, const char *filename)
{
	bool b_gzip;
	char fname[PATH_MAX];
	if (!lua_file_open_test(filename, &b_gzip, fname))
		luaL_error(L, "could not open lua file '%s' or '%s.gz'", filename, filename);
	if (b_gzip)
	{
		size_t size;
		char *buf;
		int r;
		FILE *F = fopen(fname, "rb");
		if (!F)
			luaL_error(L, "could not open lua file '%s'", fname);
		r = z_readfile(F, &buf, &size, 0);
		fclose(F);
		if (r != Z_STREAM_END)
			luaL_error(L, "could not unzip lua file '%s'", fname);
		r = luaL_loadbuffer(L, buf, size, fname);
		free(buf);
		if (!r) r=lua_pcall(L, 0, LUA_MULTRET, 0);
		return r;
	}
	else
		return luaL_dofile(L, fname);
}

static bool lua_init_scripts(void)
{
	struct str_list *str;
	int status;

	LIST_FOREACH(str, &params.lua_init_scripts, next)
	{
		if (bQuit) return false;
		if (params.debug)
		{
			if (str->str[0]=='@')
				DLOG("LUA RUN FILE: %s\n",str->str+1);
			else
			{
				char s[128];
				snprintf(s,sizeof(s),"%s",str->str);
				DLOG("LUA RUN STR: %s\n",s);
			}
		}
		if ((status = str->str[0]=='@' ? luaL_doZfile(params.L, str->str+1) : luaL_dostring(params.L, str->str)))
		{
			lua_perror(params.L);
			return false;
		}
	}
	return true;
}

static void lua_sec_harden(void)
{
	LUA_STACK_GUARD_ENTER(params.L)

	// remove unwanted functions. lua scripts are not intended to execute files
	const struct
	{
		const char *global, *field, *field2;
	} bad[] = {
		{"os","execute",NULL},
		{"io","popen",NULL},
		{"package","loadlib",NULL},
		{"debug", NULL, NULL},
		{"package", "loaded", "debug"}
	};
	DLOG("LUA REMOVE:");
	for (int i=0;i<sizeof(bad)/sizeof(*bad);i++)
	{
		if (bad[i].field)
		{
			lua_getglobal(params.L, bad[i].global);
			if (bad[i].field2)
			{
				lua_getfield(params.L, -1, bad[i].field);
				lua_pushstring(params.L, bad[i].field2);
				DLOG(" %s.%s.%s", bad[i].global, bad[i].field, bad[i].field2);
			}
			else
			{
				lua_pushstring(params.L, bad[i].field);
				DLOG(" %s.%s", bad[i].global, bad[i].field);
			}
			lua_pushnil(params.L);
			lua_rawset(params.L, -3);
			lua_pop(params.L,1 + !!bad[i].field2);
		}
		else
		{
			lua_pushnil(params.L);
			lua_setglobal(params.L, bad[i].global);
			DLOG(" %s", bad[i].global);
		}
	}
	DLOG("\n");

	LUA_STACK_GUARD_LEAVE(params.L,0)
}

static void lua_init_blobs(void)
{
	LUA_STACK_GUARD_ENTER(params.L)

	struct blob_item *blob;
	// save some memory - destroy C blobs as they are not needed anymore
	while ((blob = LIST_FIRST(&params.blobs)))
	{
		LIST_REMOVE(blob, next);
		DLOG("LUA BLOB: %s (size=%zu)\n",blob->name, blob->size);
		lua_pushlstring(params.L, (char*)blob->data, blob->size);
		lua_setglobal(params.L, blob->name);
		blob_destroy(blob);
	}

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}

static void lua_init_const(void)
{
	LUA_STACK_GUARD_ENTER(params.L)

	const struct
	{
		const char *name, *v;
	} cstr[] = {
		{"NFQWS2_VER",params.verstr}
	};

	DLOG("LUA STR:");
	for (int i=0;i<sizeof(cstr)/sizeof(*cstr);i++)
	{
		lua_pushstring(params.L, cstr[i].v);
		lua_setglobal(params.L, cstr[i].name);
		DLOG(" %s", cstr[i].name);
	}

	const struct
	{
		const char *name;
		unsigned int v;
	} cuint[] = {
#ifdef __linux__
		{"qnum",params.qnum},
#elif defined(BSD)
		{"divert_port",params.port},
#endif
		{"desync_fwmark",params.desync_fwmark},
		{"NFQWS2_COMPAT_VER",LUA_COMPAT_VER},

		{"VERDICT_PASS",VERDICT_PASS},
		{"VERDICT_MODIFY",VERDICT_MODIFY},
		{"VERDICT_DROP",VERDICT_DROP},
		{"VERDICT_MASK",VERDICT_MASK},
		{"VERDICT_PRESERVE_NEXT",VERDICT_PRESERVE_NEXT},

		{"DEFAULT_MSS",DEFAULT_MSS},

		{"IP_BASE_LEN",sizeof(struct ip)},
		{"IP6_BASE_LEN",sizeof(struct ip6_hdr)},
		{"TCP_BASE_LEN",sizeof(struct tcphdr)},
		{"UDP_BASE_LEN",sizeof(struct udphdr)},
		{"ICMP_BASE_LEN",sizeof(struct icmp46)},

		{"TCP_KIND_END",TCP_KIND_END},
		{"TCP_KIND_NOOP",TCP_KIND_NOOP},
		{"TCP_KIND_MSS",TCP_KIND_MSS},
		{"TCP_KIND_SCALE",TCP_KIND_SCALE},
		{"TCP_KIND_SACK_PERM",TCP_KIND_SACK_PERM},
		{"TCP_KIND_SACK",TCP_KIND_SACK},
		{"TCP_KIND_TS",TCP_KIND_TS},
		{"TCP_KIND_MD5",TCP_KIND_MD5},
		{"TCP_KIND_AO",TCP_KIND_AO},
		{"TCP_KIND_FASTOPEN",TCP_KIND_FASTOPEN},

		{"TH_FIN",TH_FIN},
		{"TH_SYN",TH_SYN},
		{"TH_RST",TH_RST},
		{"TH_PUSH",TH_PUSH},
		{"TH_ACK",TH_ACK},
		{"TH_FIN",TH_FIN},
		{"TH_URG",TH_URG},
		{"TH_ECE",0x40},
		{"TH_CWR",0x80},

		{"IP_RF",IP_RF},
		{"IP_DF",IP_DF},
		{"IP_MF",IP_MF},
		{"IP_OFFMASK",IP_OFFMASK},
		{"IP_FLAGMASK",IP_RF|IP_DF|IP_MF},
		{"IPTOS_ECN_MASK",IPTOS_ECN_MASK},
		{"IPTOS_ECN_NOT_ECT",0},
		{"IPTOS_ECN_ECT1",IPTOS_ECN_ECT1},
		{"IPTOS_ECN_ECT0",IPTOS_ECN_ECT0},
		{"IPTOS_ECN_CE",IPTOS_ECN_CE},
		{"IPTOS_DSCP_MASK",0xFC},
		{"IP6F_MORE_FRAG",0x0001}, // in ip6.h it's defined depending of machine byte order
		{"IPV6_FLOWLABEL_MASK",0x000FFFFF},
		{"IPV6_FLOWINFO_MASK",0x0FFFFFFF},

		{"IPPROTO_IP",IPPROTO_IP},
		{"IPPROTO_IPIP",IPPROTO_IPIP},
		{"IPPROTO_IPV6",IPPROTO_IPV6},
		{"IPPROTO_ICMP",IPPROTO_ICMP},
		{"IPPROTO_TCP",IPPROTO_TCP},
		{"IPPROTO_UDP",IPPROTO_UDP},
		{"IPPROTO_ICMPV6",IPPROTO_ICMPV6},
		{"IPPROTO_SCTP",IPPROTO_SCTP},
		{"IPPROTO_HOPOPTS",IPPROTO_HOPOPTS},
		{"IPPROTO_ROUTING",IPPROTO_ROUTING},
		{"IPPROTO_FRAGMENT",IPPROTO_FRAGMENT},
		{"IPPROTO_AH",IPPROTO_AH},
		{"IPPROTO_ESP",IPPROTO_ESP},
		{"IPPROTO_DSTOPTS",IPPROTO_DSTOPTS},
		{"IPPROTO_MH",IPPROTO_MH},
		{"IPPROTO_HIP",IPPROTO_HIP},
		{"IPPROTO_SHIM6",IPPROTO_SHIM6},
		{"IPPROTO_NONE",IPPROTO_NONE},

		// icmp types
		{"ICMP_ECHOREPLY",ICMP_ECHOREPLY},
		{"ICMP_DEST_UNREACH",ICMP_DEST_UNREACH},
		{"ICMP_REDIRECT",ICMP_REDIRECT},
		{"ICMP_ECHO",ICMP_ECHO},
		{"ICMP_TIME_EXCEEDED",ICMP_TIME_EXCEEDED},
		{"ICMP_PARAMETERPROB",ICMP_PARAMETERPROB},
		{"ICMP_TIMESTAMP",ICMP_TIMESTAMP},
		{"ICMP_TIMESTAMPREPLY",ICMP_TIMESTAMPREPLY},
		{"ICMP_INFO_REQUEST",ICMP_INFO_REQUEST},
		{"ICMP_INFO_REPLY",ICMP_INFO_REPLY},

		// icmp codes for UNREACH
		{"ICMP_UNREACH_NET",ICMP_UNREACH_NET},
		{"ICMP_UNREACH_HOST",ICMP_UNREACH_HOST},
		{"ICMP_UNREACH_PROTOCOL",ICMP_UNREACH_PROTOCOL},
		{"ICMP_UNREACH_PORT",ICMP_UNREACH_PORT},
		{"ICMP_UNREACH_NEEDFRAG",ICMP_UNREACH_NEEDFRAG},
		{"ICMP_UNREACH_SRCFAIL",ICMP_UNREACH_SRCFAIL},
		{"ICMP_UNREACH_NET_UNKNOWN",ICMP_UNREACH_NET_UNKNOWN},
		{"ICMP_UNREACH_HOST_UNKNOWN",ICMP_UNREACH_HOST_UNKNOWN},
		{"ICMP_UNREACH_NET_PROHIB",ICMP_UNREACH_NET_PROHIB},
		{"ICMP_UNREACH_HOST_PROHIB",ICMP_UNREACH_HOST_PROHIB},
		{"ICMP_UNREACH_TOSNET",ICMP_UNREACH_TOSNET},
		{"ICMP_UNREACH_TOSHOST",ICMP_UNREACH_TOSHOST},
		{"ICMP_UNREACH_FILTER_PROHIB",ICMP_UNREACH_FILTER_PROHIB},
		{"ICMP_UNREACH_HOST_PRECEDENCE",ICMP_UNREACH_HOST_PRECEDENCE},
		{"ICMP_UNREACH_PRECEDENCE_CUTOFF",ICMP_UNREACH_PRECEDENCE_CUTOFF},

		// icmp codes for REDIRECT
		{"ICMP_REDIRECT_NET",ICMP_REDIRECT_NET},
		{"ICMP_REDIRECT_HOST",ICMP_REDIRECT_HOST},
		{"ICMP_REDIRECT_TOSNET",ICMP_REDIRECT_TOSNET},
		{"ICMP_REDIRECT_TOSHOST",ICMP_REDIRECT_TOSHOST},

		// icmp codes for TIME_EXCEEDED
		{"ICMP_TIMXCEED_INTRANS",ICMP_TIMXCEED_INTRANS},
		{"ICMP_TIMXCEED_REASS",ICMP_TIMXCEED_REASS},

		// icmp6 types
		{"ICMP6_ECHO_REQUEST",ICMP6_ECHO_REQUEST},
		{"ICMP6_ECHO_REPLY",ICMP6_ECHO_REPLY},
		{"ICMP6_DST_UNREACH",ICMP6_DST_UNREACH},
		{"ICMP6_PACKET_TOO_BIG",ICMP6_PACKET_TOO_BIG},
		{"ICMP6_TIME_EXCEEDED",ICMP6_TIME_EXCEEDED},
		{"ICMP6_PARAM_PROB",ICMP6_PARAM_PROB},
		{"MLD_LISTENER_QUERY",MLD_LISTENER_QUERY},
		{"MLD_LISTENER_REPORT",MLD_LISTENER_REPORT},
		{"MLD_LISTENER_REDUCTION",MLD_LISTENER_REDUCTION},
		{"ND_ROUTER_SOLICIT",ND_ROUTER_SOLICIT},
		{"ND_ROUTER_ADVERT",ND_ROUTER_ADVERT},
		{"ND_NEIGHBOR_SOLICIT",ND_NEIGHBOR_SOLICIT},
		{"ND_NEIGHBOR_ADVERT",ND_NEIGHBOR_ADVERT},
		{"ND_REDIRECT",ND_REDIRECT},

		// icmp codes for ICMP6_DST_UNREACH
		{"ICMP6_DST_UNREACH_NOROUTE",ICMP6_DST_UNREACH_NOROUTE},
		{"ICMP6_DST_UNREACH_ADMIN",ICMP6_DST_UNREACH_ADMIN},
		{"ICMP6_DST_UNREACH_BEYONDSCOPE",ICMP6_DST_UNREACH_BEYONDSCOPE},
		{"ICMP6_DST_UNREACH_ADDR",ICMP6_DST_UNREACH_ADDR},
		{"ICMP6_DST_UNREACH_NOPORT",ICMP6_DST_UNREACH_NOPORT},

		// icmp codes for ICMP6_TIME_EXCEEDED
		{"ICMP6_TIME_EXCEED_TRANSIT",ICMP6_TIME_EXCEED_TRANSIT},
		{"ICMP6_TIME_EXCEED_REASSEMBLY",ICMP6_TIME_EXCEED_REASSEMBLY},

		// icmp codes for ICMP6_PARAM_PROB
		{"ICMP6_PARAMPROB_HEADER",ICMP6_PARAMPROB_HEADER},
		{"ICMP6_PARAMPROB_NEXTHEADER",ICMP6_PARAMPROB_NEXTHEADER},
		{"ICMP6_PARAMPROB_OPTION",ICMP6_PARAMPROB_OPTION}
	};
	DLOG("\nLUA NUMERIC:");
	for (int i=0;i<sizeof(cuint)/sizeof(*cuint);i++)
	{
		lua_pushinteger(params.L, (lua_Integer)cuint[i].v);
		lua_setglobal(params.L, cuint[i].name);
		DLOG(" %s", cuint[i].name);
	}

	DLOG("\nLUA BOOL:");
	const struct
	{
		const char *name;
		bool v;
	} cbool[] = {
		{"b_debug",params.debug},
		{"b_daemon",params.daemon},
		{"b_server",params.server},
		{"b_ipcache_hostname",params.cache_hostname},
		{"b_ctrack_disable",params.ctrack_disable}
	};
	for (int i=0;i<sizeof(cbool)/sizeof(*cbool);i++)
	{
		lua_pushboolean(params.L, cbool[i].v);
		lua_setglobal(params.L, cbool[i].name);
		DLOG(" %s", cbool[i].name);
	}

	DLOG("\n");

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}

static void lua_init_functions(void)
{
	LUA_STACK_GUARD_ENTER(params.L)

	const struct
	{
		const char *name;
		lua_CFunction f;
	} lfunc[] = {
		// logging
		{"DLOG",luacall_DLOG},
		{"DLOG_ERR",luacall_DLOG_ERR},
		{"DLOG_CONDUP",luacall_DLOG_CONDUP},

		// ip blob to string with ip version autodetect
		{"ntop",luacall_ntop},
		// string to ip blob with ip version autodetect
		{"pton",luacall_pton},

		// bit manipulation
		{"bitlshift",luacall_bitlshift},
		{"bitrshift",luacall_bitrshift},
		{"bitand",luacall_bitand},
		{"bitor",luacall_bitor},
		{"bitxor",luacall_bitxor},
		{"bitget",luacall_bitget},
		{"bitset",luacall_bitset},
		{"bitnot",luacall_bitnot48},
		{"bitnot8",luacall_bitnot8},
		{"bitnot16",luacall_bitnot16},
		{"bitnot24",luacall_bitnot24},
		{"bitnot32",luacall_bitnot32},
		{"bitnot48",luacall_bitnot48},

		// WARNING : lua 5.1 and luajit does not correctly implement integers. they seem to be stored as float which can't hold 64-bit.
		// convert part of the blob (string) to number
		{"u8",luacall_u8},
		{"u16",luacall_u16},
		{"u24",luacall_u24},
		{"u32",luacall_u32},
		{"u48",luacall_u48},
		// add any number of arguments as they would be unsigned int of specific size
		{"u8add",luacall_u8add},
		{"u16add",luacall_u16add},
		{"u24add",luacall_u24add},
		{"u32add",luacall_u32add},
		{"u48add",luacall_u48add},
		// convert number to blob (string) - big endian
		{"bu8",luacall_bu8},
		{"bu16",luacall_bu16},
		{"bu24",luacall_bu24},
		{"bu32",luacall_bu32},
		{"bu48",luacall_bu48},
		// swap byte order
		{"swap16",luacall_swap16},
		{"swap24",luacall_swap24},
		{"swap32",luacall_swap32},
		{"swap48",luacall_swap48},

		// integer division
		{"divint",luacall_divint},

		// hacky function, write to immutable strings
		//{"memcpy",luacall_memcpy},

		// random blob generation
		{"brandom",luacall_brandom},
		{"brandom_az",luacall_brandom_az},
		{"brandom_az09",luacall_brandom_az09},

		// crypto
		{"bcryptorandom",luacall_bcryptorandom},
		{"bxor",luacall_bxor},
		{"bor",luacall_bor},
		{"band",luacall_band},
		{"hash",luacall_hash},
		{"aes",luacall_aes},
		{"aes_gcm",luacall_aes_gcm},
		{"aes_ctr",luacall_aes_ctr},
		{"hkdf",luacall_hkdf},

		// parsing
		{"parse_hex",luacall_parse_hex},

		// voluntarily stop receiving packets
		{"instance_cutoff",luacall_instance_cutoff},
		// voluntarily stop receiving packets of the current connection for all instances
		{"lua_cutoff",luacall_lua_cutoff},
		// get info about upcoming desync instances and their arguments
		{"execution_plan",luacall_execution_plan},
		// cancel execution of upcoming desync instances and their arguments
		{"execution_plan_cancel",luacall_execution_plan_cancel},
		// get raw packet data
		{"raw_packet",luacall_raw_packet},

		// system functions
		{"uname",luacall_uname},
		{"clock_gettime",luacall_clock_gettime},
		{"clock_getfloattime",luacall_clock_getfloattime},
		{"getpid",luacall_getpid},
		{"gettid",luacall_gettid},

		// convert table representation to blob or vise versa
		{"reconstruct_tcphdr",luacall_reconstruct_tcphdr},
		{"reconstruct_udphdr",luacall_reconstruct_udphdr},
		{"reconstruct_icmphdr",luacall_reconstruct_icmphdr},
		{"reconstruct_ip6hdr",luacall_reconstruct_ip6hdr},
		{"reconstruct_iphdr",luacall_reconstruct_iphdr},
		{"reconstruct_dissect",luacall_reconstruct_dissect},
		{"dissect_tcphdr",luacall_dissect_tcphdr},
		{"dissect_udphdr",luacall_dissect_udphdr},
		{"dissect_icmphdr",luacall_dissect_icmphdr},
		{"dissect_ip6hdr",luacall_dissect_ip6hdr},
		{"dissect_iphdr",luacall_dissect_iphdr},
		{"dissect",luacall_dissect},
		{"csum_ip4_fix",luacall_csum_ip4_fix},
		{"csum_tcp_fix",luacall_csum_tcp_fix},
		{"csum_udp_fix",luacall_csum_udp_fix},
		{"csum_icmp_fix",luacall_csum_icmp_fix},

		// send packets
		{"rawsend",luacall_rawsend},
		{"rawsend_dissect",luacall_rawsend_dissect},

		// conntrack inject packet
		{"conntrack_feed",luacall_conntrack_feed},

		// get source addr when connecting to specified target addr
		{"get_source_ip",luacall_get_source_ip},
		// get os interface intformation
		{"get_ifaddrs",luacall_get_ifaddrs},

		// resolve position markers in any supported payload
		{"resolve_pos",luacall_resolve_pos},
		{"resolve_multi_pos",luacall_resolve_multi_pos},
		{"resolve_range",luacall_resolve_range},

		// tls
		{"tls_mod",luacall_tls_mod},

		// gzip decompress
		{"gunzip_init",luacall_gunzip_init},
		{"gunzip_end",luacall_gunzip_end},
		{"gunzip_inflate",luacall_gunzip_inflate},
		// gzip compress
		{"gzip_init",luacall_gzip_init},
		{"gzip_end",luacall_gzip_end},
		{"gzip_deflate",luacall_gzip_deflate},

		// stat() - file size, mod time
		{"stat",luacall_stat},

		// time
		{"localtime",luacall_localtime},
		{"gmtime",luacall_gmtime},
		{"timelocal",luacall_timelocal},
		{"timegm",luacall_timegm},

		// timers
		{"timer_set",luacall_timer_set},
		{"timer_del",luacall_timer_del},
		{"timer_info",luacall_timer_info},
		{"timer_enum",luacall_timer_enum}
	};
	for(int i=0;i<(sizeof(lfunc)/sizeof(*lfunc));i++)
		lua_register(params.L,lfunc[i].name,lfunc[i].f);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}

static void lua_init_mt()
{
	lua_mt_init_zstream(params.L);
	lua_mt_init_desync_ctx(params.L);
	lua_desync_ctx_create(params.L);
}

static void lua_interrupt_hook(lua_State *L, lua_Debug *ar)
{
	// avoid infinite loops
	lua_sethook(L, NULL, 0, 0); 
	luaL_error(L, "INTERRUPT"); 
}
void lua_req_quit(void)
{
	if (params.L) lua_sethook(params.L, lua_interrupt_hook, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT | LUA_MASKLINE, 1);
}

bool lua_init(void)
{
	DLOG("\nLUA INIT\n");

	if (!lua_basic_init()) return false;

	LUA_STACK_GUARD_ENTER(params.L)

	lua_sec_harden();
	lua_init_blobs();
	lua_init_const();
	lua_init_functions();
	lua_init_mt();
	if (!lua_init_scripts()) goto err;
	if (!lua_desync_functions_exist()) goto err;

	LUA_STACK_GUARD_LEAVE(params.L,0)
	DLOG("LUA INIT DONE\n\n");
	return true;
err:
	LUA_STACK_GUARD_LEAVE(params.L,0)
	lua_shutdown();
	return false;
}

void lua_dlog_error(void)
{
	if (lua_isstring(params.L, -1))
	{
		const char *error_message = lua_tostring(params.L, -1);
		DLOG_ERR("LUA ERROR: %s\n", error_message);
	}
	lua_pop(params.L, 1);
}


static time_t gc_time=0;
void lua_do_gc(void)
{
	if (params.lua_gc)
	{
		time_t now = time(NULL);
		if ((now - gc_time) >= params.lua_gc)
		{
			int kb1 = lua_gc(params.L, LUA_GCCOUNT, 0);
			lua_gc(params.L, LUA_GCCOLLECT, 0);
			int kb2 = lua_gc(params.L, LUA_GCCOUNT, 0);
			DLOG("\nLUA GARBAGE COLLECT: %dK => %dK\n",kb1,kb2);
			gc_time = now;
		}
	}
}
