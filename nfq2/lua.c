#include <time.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __FreeBSD__
#include <sys/thr.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#elif defined(__CYGWIN__)
#include <processthreadsapi.h>
#endif

#include "lua.h"
#include "params.h"
#include "helpers.h"
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
	return idx<0 ? lua_gettop(params.L) + idx + 1 : idx;
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

static int luacall_bitlshift(lua_State *L)
{
	lua_check_argc(L,"bitlshift",2);
	int64_t v=(int64_t)luaL_checklint(L,1);
	if (v>0xFFFFFFFF || v<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
	lua_pushlint(L,((uint32_t)v) << luaL_checkinteger(L,2));
	return 1;
}
static int luacall_bitrshift(lua_State *L)
{
	lua_check_argc(L,"bitrshift",2);
	int64_t v=(int64_t)luaL_checklint(L,1);
	if (v>0xFFFFFFFF || v<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
	lua_pushlint(L,((uint32_t)v) >> luaL_checkinteger(L,2));
	return 1;
}
static int luacall_bitand(lua_State *L)
{
	lua_check_argc_range(L,"bitand",2,100);
	int argc = lua_gettop(L);
	int64_t v;
	uint32_t sum=0xFFFFFFFF;
	for(int i=1;i<=argc;i++)
	{
		v=(int64_t)luaL_checklint(L,i);
		if (v>0xFFFFFFFF || v<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
		sum&=(uint32_t)v;
	}
	lua_pushlint(L,sum);
	return 1;
}
static int luacall_bitor(lua_State *L)
{
	lua_check_argc_range(L,"bitor",1,100);
	int argc = lua_gettop(L);
	int64_t v;
	uint32_t sum=0;
	for(int i=1;i<=argc;i++)
	{
		v=(int64_t)luaL_checklint(L,i);
		if (v>0xFFFFFFFF || v<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
		sum|=(uint32_t)v;
	}
	lua_pushlint(L,sum);
	return 1;
}
static int luacall_bitnot(lua_State *L)
{
	lua_check_argc(L,"bitnot",1);
	lua_pushlint(L,~(uint32_t)luaL_checklint(L,1));
	return 1;
}
static int luacall_bitxor(lua_State *L)
{
	lua_check_argc_range(L,"bitxor",1,100);
	int argc = lua_gettop(L);
	int64_t v;
	uint32_t sum=0;
	for(int i=1;i<=argc;i++)
	{
		v=(int64_t)luaL_checklint(L,i);
		if (v>0xFFFFFFFF || v<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
		sum^=(uint32_t)v;
	}
	lua_pushlint(L,sum);
	return 1;
}
static int luacall_bitget(lua_State *L)
{
	lua_check_argc(L,"bitget",3);

	int64_t iwhat = (int64_t)luaL_checklint(L,1);
	if (iwhat>0xFFFFFFFF || iwhat<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
	uint32_t what = (uint32_t)iwhat;
	lua_Integer from = luaL_checkinteger(L,2);
	lua_Integer to = luaL_checkinteger(L,3);
	if (from>to || from>31 || to>31)
		luaL_error(L, "bit range invalid");

	what = (what >> from) & ~((lua_Integer)-1 << (to-from+1));

	lua_pushlint(L,what);
	return 1;
}
static int luacall_bitset(lua_State *L)
{
	lua_check_argc(L,"bitset",4);

	int64_t iwhat = (int64_t)luaL_checklint(L,1);
	if (iwhat>0xFFFFFFFF || iwhat<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
	uint32_t what = (uint32_t)iwhat;
	lua_Integer from = luaL_checkinteger(L,2);
	lua_Integer to = luaL_checkinteger(L,3);
	int64_t iset = (int64_t)luaL_checklint(L,4);
	if (iset>0xFFFFFFFF || iset<-(int64_t)0xFFFFFFFF) luaL_error(L, "out of range");
	uint32_t set = (uint32_t)iset;
	if (from>to || from>31 || to>31)
		luaL_error(L, "bit range invalid");

	lua_Integer mask = ~((lua_Integer)-1 << (to-from+1));
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
	const uint8_t *p = (uint8_t*)luaL_checklstring(L,1,&l);
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
	const uint8_t *p = (uint8_t*)luaL_checklstring(L,1,&l);
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
	const uint8_t *p = (uint8_t*)luaL_checklstring(L,1,&l);
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
	const uint8_t *p = (uint8_t*)luaL_checklstring(L,1,&l);
	offset = (argc>=2 && lua_type(L,2)!=LUA_TNIL) ? luaL_checkinteger(L,2)-1 : 0;
	if (offset<0 || (offset+4)>l) luaL_error(L, "out of range");

	lua_pushlint(L,pntoh32(p+offset));
	return 1;
}
static int luacall_swap16(lua_State *L)
{
	lua_check_argc(L,"swap16",1);

	int64_t i = (int64_t)luaL_checklint(L,1);
	if (i>0xFFFF || i<-(int64_t)0xFFFF) luaL_error(L, "out of range");
	uint16_t u = (uint16_t)i;
	// __builtin_bswap16 is absent in ancient lexra gcc 4.6
	lua_pushinteger(L,(u>>8) | ((u&0xFF)<<8));
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
static int lua_uxadd(lua_State *L, uint32_t max)
{
	int64_t v;
	uint32_t sum=0;
	int argc = lua_gettop(L);
	for(int i=1;i<=argc;i++)
	{
		v = (int64_t)luaL_checklint(L,i);
		if (v>max || v<-(int64_t)max) luaL_error(L, "out of range");
		sum+=(uint32_t)v;
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
	lua_Integer len = luaL_checkinteger(L,1);

	uint8_t *p = malloc(len);
	if (!p) luaL_error(L, "out of memory");
	fill_random_bytes(p,len);
	// in out of memory condition this will leave p unfreed
	lua_pushlstring(L,(char*)p,len);
	free(p);
	return 1;
}
static int luacall_brandom_az(lua_State *L)
{
	lua_check_argc(L,"brandom_az",1);
	lua_Integer len = luaL_checkinteger(L,1);

	uint8_t *p = malloc(len);
	if (!p) luaL_error(L, "out of memory");
	fill_random_az(p,len);
	// in out of memory condition this will leave p unfreed
	lua_pushlstring(L,(char*)p,len);
	free(p);
	return 1;
}
static int luacall_brandom_az09(lua_State *L)
{
	lua_check_argc(L,"brandom_az09",1);
	lua_Integer len = luaL_checkinteger(L,1);

	uint8_t *p = malloc(len);
	if (!p) luaL_error(L, "out of memory");
	fill_random_az09(p,len);
	// in out of memory condition this will leave p unfreed
	lua_pushlstring(L,(char*)p,len);
	free(p);
	return 1;
}

// hacky function. breaks immutable string behavior.
// if you change a string, it will change in all variables that hold the same string
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


static int luacall_parse_hex(lua_State *L)
{
	lua_check_argc(L,"parse_hex",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t l;
	const char *hex = lua_tolstring(L,1,&l);
	if ((l&1)) goto err;
	l>>=1;
	uint8_t *p = malloc(l);
	if (!p) goto err;
	if (!parse_hex_str(hex,p,&l))
	{
		free(p);
		goto err;
	}
	// in out of memory condition this will leave p unfreed
	lua_pushlstring(L,(char*)p,l);
	free(p);
ex:
	LUA_STACK_GUARD_RETURN(L,1)
err:
	lua_pushnil(L);
	goto ex;
}



static SHAversion lua_hash_type(const char *s_hash_type)
{
	SHAversion sha_ver;
	if (!strcmp(s_hash_type,"sha256"))
		sha_ver = SHA256;
	else if (!strcmp(s_hash_type,"sha224"))
		sha_ver = SHA224;
	else
		luaL_error(params.L, "unsupported hash type %s", s_hash_type);
	return sha_ver;
}

static int luacall_bcryptorandom(lua_State *L)
{
	lua_check_argc(L,"bcryptorandom",1);

	LUA_STACK_GUARD_ENTER(L)

	lua_Integer len = luaL_checkinteger(L,1);

	uint8_t *p = malloc(len);
	if (!p) luaL_error(L, "out of memory");

	if (!fill_crypto_random_bytes(p,len))
	{
		free(p);
		// this is fatal. they expect us to give them crypto secure random blob
		luaL_error(L, "could not read random data from /dev/random");
	}

	lua_pushlstring(L,(char*)p,len);
	free(p);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_hash(lua_State *L)
{
	// hash(hash_type, data) returns hash
	lua_check_argc(L,"hash",2);

	LUA_STACK_GUARD_ENTER(L)

	const char *s_hash_type =  luaL_checkstring(L,1);
	SHAversion sha_ver = lua_hash_type(s_hash_type);

	size_t data_len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,2,&data_len);

	unsigned char hash[USHAMaxHashSize];
	USHAContext tcontext;
	if (USHAReset(&tcontext, sha_ver)!=shaSuccess || USHAInput(&tcontext, data, data_len)!=shaSuccess || USHAResult(&tcontext, hash)!=shaSuccess)
		luaL_error(L, "hash failure");

	lua_pushlstring(L,(char*)hash,USHAHashSize(sha_ver));

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_aes(lua_State *L)
{
	// aes_gcm(bEncrypt, key, in) returns out
	lua_check_argc(L,"aes",3);

	LUA_STACK_GUARD_ENTER(L)

	bool bEncrypt = lua_toboolean(L,1);
	size_t key_len;
	const uint8_t *key = (uint8_t*)luaL_checklstring(L,2,&key_len);
	if (key_len!=16 && key_len!=24 && key_len!=32)
		luaL_error(L, "aes: wrong key length %u. should be 16,24,32.", (unsigned)key_len);
	size_t input_len;
	const uint8_t *input = (uint8_t*)luaL_checklstring(L,3,&input_len);
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
	const uint8_t *key = (uint8_t*)luaL_checklstring(L,2,&key_len);
	if (key_len!=16 && key_len!=24 && key_len!=32)
		luaL_error(L, "aes_gcm: wrong key length %u. should be 16,24,32.", (unsigned)key_len);
	size_t iv_len;
	const uint8_t *iv = (uint8_t*)luaL_checklstring(L,3,&iv_len);
	if (iv_len!=12)
		luaL_error(L, "aes_gcm: wrong iv length %u. should be 12.", (unsigned)iv_len);
	size_t input_len;
	const uint8_t *input = (uint8_t*)luaL_checklstring(L,4,&input_len);
	size_t add_len=0;
	const uint8_t *add = lua_isnoneornil(L,5) ? NULL : (uint8_t*)luaL_checklstring(L,5,&add_len);

	uint8_t atag[16];
	uint8_t *output = malloc(input_len);
	if (!output) luaL_error(L, "out of memory");

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
	free(output);

	LUA_STACK_GUARD_RETURN(L,2)
}

static int luacall_aes_ctr(lua_State *L)
{
	// aes_ctr(key, iv, in) returns out
	lua_check_argc(L,"aes_ctr",3);

	LUA_STACK_GUARD_ENTER(L)

	size_t key_len;
	const uint8_t *key = (uint8_t*)luaL_checklstring(L,1,&key_len);
	if (key_len!=16 && key_len!=24 && key_len!=32)
		luaL_error(L, "aes_ctr: wrong key length %u. should be 16,24,32.", (unsigned)key_len);

	size_t iv_len;
	const uint8_t *iv = (uint8_t*)luaL_checklstring(L,2,&iv_len);
	if (iv_len!=16)
		luaL_error(L, "aes_ctr: wrong iv length %u. should be 16.", (unsigned)iv_len);

	size_t input_len;
	const uint8_t *input = (uint8_t*)luaL_checklstring(L,3,&input_len);

	uint8_t *output = malloc(input_len);
	if (!output) luaL_error(L, "out of memory");

	if (aes_ctr_crypt(key, key_len, iv, input, input_len, output))
		lua_pushnil(L);
	else
		lua_pushlstring(L,(const char*)output,input_len);
	free(output);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_hkdf(lua_State *L)
{
	// hkdf(hash_type, salt, ikm, info, okm_len) returns okm
	// hash_type - string "sha224" or "sha256"
	lua_check_argc(L,"hkdf",5);

	LUA_STACK_GUARD_ENTER(L)

	const char *s_hash_type =  luaL_checkstring(L,1);
	SHAversion sha_ver = lua_hash_type(s_hash_type);
	size_t salt_len=0;
	const uint8_t *salt = lua_type(L,2) == LUA_TNIL ? NULL : (uint8_t*)luaL_checklstring(L,2,&salt_len);
	size_t ikm_len=0;
	const uint8_t *ikm = lua_type(L,3) == LUA_TNIL ? NULL : (uint8_t*)luaL_checklstring(L,3,&ikm_len);
	size_t info_len=0;
	const uint8_t *info = lua_type(L,4) == LUA_TNIL ? NULL : (uint8_t*)luaL_checklstring(L,4,&info_len);
	size_t okm_len = (size_t)luaL_checkinteger(L,5);

	uint8_t *okm = malloc(okm_len);
	if (!okm) luaL_error(L, "out of memory");

	if (hkdf(sha_ver, salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len))
		lua_pushnil(L);
	else
		lua_pushlstring(L,(const char*)okm, okm_len);

	free(okm);

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
		lua_createtable(params.L, 0, 5);
		lua_pushf_str("sysname", udata.sysname);
		lua_pushf_str("nodename", udata.nodename);
		lua_pushf_str("release", udata.release);
		lua_pushf_str("version", udata.version);
		lua_pushf_str("machine", udata.machine);
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

static t_lua_desync_context *lua_desync_ctx()
{
	if (lua_isnil(params.L,1))
		luaL_error(params.L, "missing ctx");
	if (!lua_islightuserdata(params.L,1))
		luaL_error(params.L, "bad ctx - invalid data type");

	t_lua_desync_context *ctx = lua_touserdata(params.L,1);
	// ensure it's really ctx. LUA could pass us any lightuserdata pointer
	if (ctx->magic!=MAGIC_CTX)
		luaL_error(params.L, "bad ctx - magic bytes invalid");

	return ctx;
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
		const t_lua_desync_context *ctx = lua_desync_ctx();

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
				lua_pushf_table(ctx->instance);
				lua_getfield(L,-1,ctx->instance);
			}
			lua_rawgeti(L,-1,ctx->dp->n);
			if (!lua_istable(L,-1))
			{
				lua_pop(L,1);
				lua_pushi_table(ctx->dp->n);
				lua_rawgeti(L,-1,ctx->dp->n);
			}
			if (bOut) lua_pushi_bool(0,true);
			if (bIn) lua_pushi_bool(1,true);
			lua_pop(L,3);
		}
		else
			DLOG("instance cutoff requested for '%s' in=%u out=%u but not possible without conntrack\n",ctx->instance,bIn,bOut);
	}

	LUA_STACK_GUARD_RETURN(L,0)
}

bool lua_instance_cutoff_check(const t_lua_desync_context *ctx, bool bIn)
{
	bool b=false;

	// out : func_name.profile_number[0]
	// in  : func_name.profile_number[1]

	if (ctx->ctrack)
	{
		lua_rawgeti(params.L,LUA_REGISTRYINDEX,ctx->ctrack->lua_instance_cutoff);
		lua_getfield(params.L,-1,ctx->instance);
		if (!lua_istable(params.L,-1))
		{
			lua_pop(params.L,2);
			return false;
		}
		lua_rawgeti(params.L,-1,ctx->dp->n);
		if (!lua_istable(params.L,-1))
		{
			lua_pop(params.L,3);
			return false;
		}
		lua_rawgeti(params.L,-1,bIn);
		b = lua_toboolean(params.L,-1);
		lua_pop(params.L,4);
	}
	return b;
}

static int luacall_lua_cutoff(lua_State *L)
{
	lua_check_argc_range(L,"lua_cutoff",1,2);

	LUA_STACK_GUARD_ENTER(L)

	t_lua_desync_context *ctx = lua_desync_ctx();

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

	t_lua_desync_context *ctx = lua_desync_ctx();

	lua_newtable(L);

	struct func_list *func;
	char instance[256], pls[2048];
	struct packet_range *range;
	unsigned int n=1;
	LIST_FOREACH(func, &ctx->dp->lua_desync, next)
	{
		if (n > ctx->func_n)
		{
			desync_instance(func->func, ctx->dp->n, n, instance, sizeof(instance));
			range = ctx->incoming ? &func->range_in : &func->range_out;
			lua_pushinteger(params.L, n - ctx->func_n);
			lua_createtable(params.L, 0, 6);
			lua_pushf_args(&func->args, -1, false);
			lua_pushf_str("func", func->func);
			lua_pushf_int("func_n", ctx->func_n);
			lua_pushf_str("func_instance", instance);
			lua_pushf_range("range", range);
			if (l7_payload_str_list(func->payload_type, pls, sizeof(pls)))
				lua_pushf_str("payload_filter", pls);
			else
				lua_pushf_nil("payload_filter");

			lua_rawset(params.L,-3);
		}
		n++;
	}

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_execution_plan_cancel(lua_State *L)
{
	lua_check_argc(L,"execution_plan_cancel",1);

	t_lua_desync_context *ctx = lua_desync_ctx();

	DLOG("execution plan cancel from '%s'\n",ctx->instance);

	ctx->cancel = true;
	return 0;
}


static int luacall_raw_packet(lua_State *L)
{
	lua_check_argc(L,"raw_packet",1);

	LUA_STACK_GUARD_ENTER(L)

	const t_lua_desync_context *ctx = lua_desync_ctx();

	lua_pushlstring(L, (const char*)ctx->dis->data_pkt, ctx->dis->len_pkt);

	LUA_STACK_GUARD_RETURN(L,1)
}


void lua_pushf_nil(const char *field)
{
	lua_pushstring(params.L, field);
	lua_pushnil(params.L);
	lua_rawset(params.L,-3);
}
void lua_pushi_nil(lua_Integer idx)
{
	lua_pushinteger(params.L, idx);
	lua_pushnil(params.L);
	lua_rawset(params.L,-3);
}
void lua_pushf_int(const char *field, lua_Integer v)
{
	lua_pushstring(params.L, field);
	lua_pushlint(params.L, v);
	lua_rawset(params.L,-3);
}
void lua_pushi_int(lua_Integer idx, lua_Integer v)
{
	lua_pushinteger(params.L, idx);
	lua_pushlint(params.L, v);
	lua_rawset(params.L,-3);
}
void lua_pushf_lint(const char *field, int64_t v)
{
	lua_pushstring(params.L, field);
	lua_pushlint(params.L, v);
	lua_rawset(params.L,-3);
}
void lua_pushi_lint(lua_Integer idx, int64_t v)
{
	lua_pushinteger(params.L, idx);
	lua_pushlint(params.L, v);
	lua_rawset(params.L,-3);
}
void lua_pushf_number(const char *field, lua_Number v)
{
	lua_pushstring(params.L, field);
	lua_pushnumber(params.L, v);
	lua_rawset(params.L,-3);
}
void lua_pushi_number(lua_Integer idx, lua_Number v)
{
	lua_pushinteger(params.L, idx);
	lua_pushnumber(params.L, v);
	lua_rawset(params.L,-3);
}
void lua_pushf_bool(const char *field, bool b)
{
	lua_pushstring(params.L, field);
	lua_pushboolean(params.L, b);
	lua_rawset(params.L,-3);
}
void lua_pushi_bool(lua_Integer idx, bool b)
{
	lua_pushinteger(params.L, idx);
	lua_pushboolean(params.L, b);
	lua_rawset(params.L,-3);
}
void lua_pushf_str(const char *field, const char *str)
{
	lua_pushstring(params.L, field);
	lua_pushstring(params.L, str); // pushes nil if str==NULL
	lua_rawset(params.L,-3);
}
void lua_pushi_str(lua_Integer idx, const char *str)
{
	lua_pushinteger(params.L, idx);
	lua_pushstring(params.L, str); // pushes nil if str==NULL
	lua_rawset(params.L,-3);
}
void lua_pushf_lstr(const char *field, const char *str, size_t size)
{
	lua_pushstring(params.L, field);
	lua_pushlstring(params.L, str, size);
	lua_rawset(params.L,-3);
}
void lua_pushi_lstr(lua_Integer idx, const char *str, size_t size)
{
	lua_pushinteger(params.L, idx);
	lua_pushlstring(params.L, str, size);
	lua_rawset(params.L,-3);
}
void lua_push_raw(const void *v, size_t l)
{
	if (v)
		lua_pushlstring(params.L, (char*)v, l);
	else
		lua_pushnil(params.L);
}
void lua_pushf_raw(const char *field, const void *v, size_t l)
{
	lua_pushstring(params.L, field);
	lua_push_raw(v,l);
	lua_rawset(params.L,-3);
}
void lua_pushi_raw(lua_Integer idx, const void *v, size_t l)
{
	lua_pushinteger(params.L, idx);
	lua_push_raw(v,l);
	lua_rawset(params.L,-3);
}
void lua_pushf_reg(const char *field, int ref)
{
	lua_pushstring(params.L, field);
	lua_rawgeti(params.L, LUA_REGISTRYINDEX, ref);
	lua_rawset(params.L, -3);
}
void lua_pushf_lud(const char *field, void *p)
{
	lua_pushstring(params.L, field);
	lua_pushlightuserdata(params.L, p);
	lua_rawset(params.L,-3);
}
void lua_pushf_table(const char *field)
{
	lua_pushstring(params.L, field);
	lua_newtable(params.L);
	lua_rawset(params.L,-3);
}
void lua_pushi_table(lua_Integer idx)
{
	lua_pushinteger(params.L, idx);
	lua_newtable(params.L);
	lua_rawset(params.L,-3);
}
void lua_pushf_global(const char *field, const char *global)
{
	lua_pushstring(params.L, field);
	lua_getglobal(params.L, global);
	lua_rawset(params.L,-3);
}

void lua_push_blob(int idx_desync, const char *blob)
{
	lua_getfield(params.L, idx_desync, blob);
	if (lua_type(params.L,-1)==LUA_TNIL)
	{
		lua_pop(params.L,1);
		lua_getglobal(params.L, blob);
	}
}
void lua_pushf_blob(int idx_desync, const char *field, const char *blob)
{
	lua_pushstring(params.L, field);
	lua_push_blob(idx_desync, blob);
	lua_rawset(params.L,-3);
}


void lua_pushf_tcphdr_options(const struct tcphdr *tcp, size_t len)
{
	LUA_STACK_GUARD_ENTER(params.L)

	lua_pushliteral(params.L,"options");
	lua_newtable(params.L);

	uint8_t *t = (uint8_t*)(tcp+1);
	uint8_t *end = (uint8_t*)tcp + (tcp->th_off<<2);
	uint8_t opt;
	if ((end-(uint8_t*)tcp) < len) end=(uint8_t*)tcp + len;
	lua_Integer idx=1;
	while(t<end)
	{
		opt = *t;
		if (opt==TCP_KIND_NOOP || opt==TCP_KIND_END)
		{
			lua_pushinteger(params.L,idx);
			lua_newtable(params.L);
			lua_pushf_int("kind",opt);
			t++;
		}
		else
		{
			if ((t+1)>=end || t[1]<2 || (t+t[1])>end) break;
			lua_pushinteger(params.L,idx);
			lua_newtable(params.L);
			lua_pushf_int("kind",opt);
			lua_pushf_raw("data",t+2,t[1]-2);
			t+=t[1];
		}
		lua_rawset(params.L,-3);
		if (opt==TCP_KIND_END) break;
		idx++;
	}

	lua_rawset(params.L,-3);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}

void lua_pushf_tcphdr(const struct tcphdr *tcp, size_t len)
{
	LUA_STACK_GUARD_ENTER(params.L)

	lua_pushliteral(params.L, "tcp");
	if (tcp && len>=sizeof(struct tcphdr))
	{
		lua_createtable(params.L, 0, 11);
		lua_pushf_int("th_sport",ntohs(tcp->th_sport));
		lua_pushf_int("th_dport",ntohs(tcp->th_dport));
		lua_pushf_lint("th_seq",ntohl(tcp->th_seq));
		lua_pushf_lint("th_ack",ntohl(tcp->th_ack));
		lua_pushf_int("th_x2",tcp->th_x2);
		lua_pushf_int("th_off",tcp->th_off);
		lua_pushf_int("th_flags",tcp->th_flags);
		lua_pushf_int("th_win",ntohs(tcp->th_win));
		lua_pushf_int("th_sum",ntohs(tcp->th_sum));
		lua_pushf_int("th_urp",ntohs(tcp->th_urp));
		lua_pushf_tcphdr_options(tcp,len);
	}
	else
		lua_pushnil(params.L);
	lua_rawset(params.L,-3);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}
void lua_pushf_udphdr(const struct udphdr *udp, size_t len)
{
	LUA_STACK_GUARD_ENTER(params.L)

	lua_pushliteral(params.L, "udp");
	if (udp && len>=sizeof(struct udphdr))
	{
		lua_createtable(params.L, 0, 4);
		lua_pushf_int("uh_sport",ntohs(udp->uh_sport));
		lua_pushf_int("uh_dport",ntohs(udp->uh_dport));
		lua_pushf_int("uh_ulen",ntohs(udp->uh_ulen));
		lua_pushf_int("uh_sum",ntohs(udp->uh_sum));
	}
	else
		lua_pushnil(params.L);
	lua_rawset(params.L,-3);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}
void lua_pushf_iphdr(const struct ip *ip, size_t len)
{
	LUA_STACK_GUARD_ENTER(params.L)

	lua_pushliteral(params.L, "ip");
	if (ip && len>=sizeof(struct ip))
	{
		uint16_t hl = ip->ip_hl<<2;
		bool b_has_opt = hl>sizeof(struct tcphdr) && hl<=len;
		lua_createtable(params.L, 0, 11+b_has_opt);
		lua_pushf_int("ip_v",ip->ip_v);
		lua_pushf_int("ip_hl",ip->ip_hl);
		lua_pushf_int("ip_tos",ip->ip_tos);
		lua_pushf_int("ip_len",ntohs(ip->ip_len));
		lua_pushf_int("ip_id",ntohs(ip->ip_id));
		lua_pushf_int("ip_off",ntohs(ip->ip_off));
		lua_pushf_int("ip_ttl",ip->ip_ttl);
		lua_pushf_int("ip_p",ip->ip_p);
		lua_pushf_int("ip_sum",ip->ip_sum);
		lua_pushf_raw("ip_src",&ip->ip_src,sizeof(struct in_addr));
		lua_pushf_raw("ip_dst",&ip->ip_dst,sizeof(struct in_addr));
		if (b_has_opt)
			lua_pushf_raw("options",(uint8_t*)(ip+1),hl-sizeof(struct tcphdr));
	}
	else
		lua_pushnil(params.L);
	lua_rawset(params.L,-3);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}
void lua_pushf_ip6exthdr(const struct ip6_hdr *ip6, size_t len)
{
	LUA_STACK_GUARD_ENTER(params.L);

	// assume ipv6 packet structure was already checked for validity
	size_t hdrlen;
	uint8_t HeaderType, *data;
	lua_Integer idx = 1;

	lua_pushliteral(params.L, "exthdr");
	lua_newtable(params.L);
	if (len>=sizeof(struct ip6_hdr))
	{
		HeaderType = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		data=(uint8_t*)(ip6+1);
		len-=sizeof(struct ip6_hdr);
		while (len > 0) // need at least one byte for NextHeader field
		{
			switch (HeaderType)
			{
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
			case IPPROTO_MH: // mobility header
			case IPPROTO_HIP: // Host Identity Protocol Version v2
			case IPPROTO_SHIM6:
				if (len < 2) return; // error
				hdrlen = 8 + (data[1] << 3);
				break;
			case IPPROTO_FRAGMENT: // fragment. length fixed to 8, hdrlen field defined as reserved
				hdrlen = 8;
				break;
			case IPPROTO_AH:
				// special case. length in ah header is in 32-bit words minus 2
				if (len < 2) return; // error
				hdrlen = 8 + (data[1] << 2);
				break;
			case IPPROTO_NONE: // no next header
			default:
				// we found some meaningful payload. it can be tcp, udp, icmp or some another exotic shit
				goto end;
			}
			if (len < hdrlen) goto end; // error

			lua_pushinteger(params.L, idx++);
			lua_createtable(params.L, 0, 3);
			lua_pushf_int("type", HeaderType);
			HeaderType = *data;
			lua_pushf_int("next", HeaderType);
			lua_pushf_raw("data",data+2,hdrlen-2);
			lua_rawset(params.L,-3);

			// advance to the next header location
			len -= hdrlen;
			data += hdrlen;
		}
	}

end:
	lua_rawset(params.L,-3);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}
void lua_pushf_ip6hdr(const struct ip6_hdr *ip6, size_t len)
{
	LUA_STACK_GUARD_ENTER(params.L)

	lua_pushliteral(params.L, "ip6");
	if (ip6)
	{
		lua_createtable(params.L, 0, 7);
		lua_pushf_lint("ip6_flow",ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow));
		lua_pushf_lint("ip6_plen",ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
		lua_pushf_int("ip6_nxt",ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
		lua_pushf_int("ip6_hlim",ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
		lua_pushf_raw("ip6_src",&ip6->ip6_src,sizeof(struct in6_addr));
		lua_pushf_raw("ip6_dst",&ip6->ip6_dst,sizeof(struct in6_addr));
		lua_pushf_ip6exthdr(ip6,len);
	}
	else
		lua_pushnil(params.L);
	lua_rawset(params.L,-3);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}
void lua_push_dissect(const struct dissect *dis)
{
	LUA_STACK_GUARD_ENTER(params.L)

	if (dis)
	{
		lua_createtable(params.L, 0, 9);
		lua_pushf_iphdr(dis->ip, dis->len_l3);
		lua_pushf_ip6hdr(dis->ip6, dis->len_l3);
		lua_pushf_tcphdr(dis->tcp, dis->len_l4);
		lua_pushf_udphdr(dis->udp, dis->len_l4);
		lua_pushf_int("l4proto",dis->proto);
		lua_pushf_int("transport_len",dis->transport_len);
		lua_pushf_int("l3_len",dis->len_l3);
		lua_pushf_int("l4_len",dis->len_l4);
		lua_pushf_raw("payload",dis->data_payload,dis->len_payload);
	}
	else
		lua_pushnil(params.L);

	LUA_STACK_GUARD_LEAVE(params.L, 1)
}
void lua_pushf_dissect(const struct dissect *dis)
{
	lua_pushliteral(params.L, "dis");
	lua_push_dissect(dis);
	lua_rawset(params.L,-3);
}

void lua_pushf_ctrack_pos(const t_ctrack *ctrack, const t_ctrack_position *pos)
{
	LUA_STACK_GUARD_ENTER(params.L)

	lua_pushf_lint("pcounter", pos->pcounter);
	lua_pushf_lint("pdcounter", pos->pdcounter);
	lua_pushf_lint("pbcounter", pos->pbcounter);
	if (ctrack->ipproto == IPPROTO_TCP)
	{
		lua_pushliteral(params.L, "tcp");
		lua_createtable(params.L, 0, 12);
		lua_pushf_lint("seq0", pos->seq0);
		lua_pushf_lint("seq", pos->seq_last);
		lua_pushf_lint("rseq", pos->seq_last - pos->seq0);
		lua_pushf_bool("rseq_over_2G", pos->rseq_over_2G);
		lua_pushf_int("pos", pos->pos - pos->seq0);
		lua_pushf_int("uppos", pos->uppos - pos->seq0);
		lua_pushf_int("uppos_prev", pos->uppos_prev - pos->seq0);
		lua_pushf_int("winsize", pos->winsize);
		lua_pushf_int("winsize_calc", pos->winsize_calc);
		lua_pushf_int("scale", pos->scale);
		lua_pushf_int("mss", pos->mss);
		lua_pushf_int("ip6flow", pos->ip6flow);
		lua_rawset(params.L,-3);
	}

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}

void lua_pushf_ctrack(const t_ctrack *ctrack, const t_ctrack_positions *tpos, bool bIncoming)
{
	LUA_STACK_GUARD_ENTER(params.L)

	if (!tpos) tpos = &ctrack->pos;

	lua_pushliteral(params.L, "track");
	if (ctrack)
	{
		lua_createtable(params.L, 0, 9);

		if (ctrack->incoming_ttl)
			lua_pushf_int("incoming_ttl", ctrack->incoming_ttl);
		else
			lua_pushf_nil("incoming_ttl");
		lua_pushf_str("l7proto", l7proto_str(ctrack->l7proto));
		lua_pushf_str("hostname", ctrack->hostname);
		lua_pushf_bool("hostname_is_ip", ctrack->hostname_is_ip);
		lua_pushf_reg("lua_state", ctrack->lua_state);
		lua_pushf_bool("lua_in_cutoff", ctrack->b_lua_in_cutoff);
		lua_pushf_bool("lua_out_cutoff", ctrack->b_lua_out_cutoff);
		lua_pushf_lint("t_start", (lua_Number)ctrack->t_start.tv_sec + ctrack->t_start.tv_nsec/1000000000.);

		lua_pushliteral(params.L, "pos");
		lua_createtable(params.L, 0, 5);

		// orig, reply related to connection logical direction
		// for tcp orig is client (who connects), reply is server (who listens). 
		// for orig is the first seen party, reply is another party
		lua_pushf_number("dt",
			(lua_Number)tpos->t_last.tv_sec - (lua_Number)ctrack->t_start.tv_sec +
			(tpos->t_last.tv_nsec - ctrack->t_start.tv_nsec)/1000000000.);

		lua_pushliteral(params.L, "client");
		lua_newtable(params.L);
		lua_pushf_ctrack_pos(ctrack, &tpos->client);
		lua_rawset(params.L,-3);

		lua_pushliteral(params.L, "server");
		lua_newtable(params.L);
		lua_pushf_ctrack_pos(ctrack, &tpos->server);
		lua_rawset(params.L,-3);

		// direct and reverse are adjusted for server mode. in server mode orig and reply are exchanged.
		lua_pushliteral(params.L, "direct");
		lua_getfield(params.L, -2, (params.server ^ bIncoming) ? "server" : "client");
		lua_rawset(params.L,-3);

		lua_pushliteral(params.L, "reverse");
		lua_getfield(params.L, -2, (params.server ^ bIncoming) ? "client" : "server");
		lua_rawset(params.L,-3);

		lua_rawset(params.L,-3);
	}
	else
		lua_pushnil(params.L);
	lua_rawset(params.L,-3);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}

void lua_pushf_args(const struct str2_list_head *args, int idx_desync, bool subst_prefix)
{
	// var=val - pass val string
	// var=%val - subst 'val' blob
	// var=#val - subst 'val' blob length
	// var=\#val - no subst, skip '\'
	// var=\%val - no subst, skip '\'

	LUA_STACK_GUARD_ENTER(params.L)

	struct str2_list *arg;
	const char *var, *val;

	idx_desync = lua_absindex(params.L, idx_desync);

	lua_pushliteral(params.L,"arg");
	lua_newtable(params.L);
	LIST_FOREACH(arg, args, next)
	{
		var = arg->str1;
		val = arg->str2 ? arg->str2 : "";
		if (subst_prefix)
		{
			if (val[0]=='\\' && (val[1]=='%' || val[1]=='#'))
				// escape char
				lua_pushf_str(var, val+1);
			else if (val[0]=='%')
				lua_pushf_blob(idx_desync, var, val+1);
			else if (val[0]=='#')
			{
				lua_push_blob(idx_desync, val+1);
				lua_Integer len = lua_rawlen(params.L, -1);
				lua_pop(params.L,1);
				lua_pushf_int(var, len);
			}
			else
				lua_pushf_str(var, val);
		}
		else
			lua_pushf_str(var, val);
	}
	lua_rawset(params.L,-3);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}
void lua_pushf_pos(const char *name, const struct packet_pos *pos)
{
	LUA_STACK_GUARD_ENTER(params.L)

	char smode[2]="?";
	lua_pushf_table(name);
	lua_getfield(params.L,-1,name);
	*smode=pos->mode;
	lua_pushf_str("mode",smode);
	lua_pushf_lint("pos",pos->pos);
	lua_pop(params.L,1);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}
void lua_pushf_range(const char *name, const struct packet_range *range)
{
	LUA_STACK_GUARD_ENTER(params.L)

	lua_pushf_table(name);
	lua_getfield(params.L,-1,"range");
	lua_pushf_bool("upper_cutoff",range->upper_cutoff);
	lua_pushf_pos("from", &range->from);
	lua_pushf_pos("to", &range->to);
	lua_pop(params.L,1);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}


static void lua_reconstruct_extract_options(lua_State *L, int idx, bool *badsum, bool *ip6_preserve_next, uint8_t *ip6_last_proto)
{
	if (lua_isnoneornil(L,idx))
	{
		if (badsum) *badsum = false;
		if (ip6_preserve_next) *ip6_preserve_next = false;
		if (ip6_last_proto) *ip6_last_proto = IPPROTO_NONE;
	}
	else
	{
		luaL_checktype(L, idx, LUA_TTABLE);
		if (badsum)
		{
			lua_getfield(L,idx,"badsum");
			*badsum = lua_type(L,-1)!=LUA_TNIL && (lua_type(L,-1)!=LUA_TBOOLEAN || lua_toboolean(L,-1));
			lua_pop(L,1);
		}
		if (ip6_preserve_next)
		{
			lua_getfield(L,idx,"ip6_preserve_next");
			*ip6_preserve_next = lua_type(L,-1)!=LUA_TNIL && (lua_type(L,-1)!=LUA_TBOOLEAN || lua_toboolean(L,-1));
			lua_pop(L,1);
		}
		if (ip6_last_proto)
		{
			lua_getfield(L,idx,"ip6_last_proto");
			*ip6_last_proto = lua_type(L,-1)==LUA_TNIL ? IPPROTO_NONE : (uint8_t)lua_tointeger(L,-1);
			lua_pop(L,1);
		}
	}
}


static bool lua_reconstruct_ip6exthdr(int idx, struct ip6_hdr *ip6, size_t *len, uint8_t proto, bool preserve_next)
{
	LUA_STACK_GUARD_ENTER(params.L)

	// proto = last header type
	if (*len<sizeof(struct tcphdr)) return false;

	uint8_t *last_proto = &ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	uint8_t filled = sizeof(struct ip6_hdr);
	lua_getfield(params.L,idx,"exthdr");
	if (lua_type(params.L,-1)==LUA_TTABLE)
	{
		lua_Integer idx=0;
		uint8_t next, type, *p, *data = (uint8_t*)(ip6+1);
		size_t l, left;

	 	left = *len - filled;

		for(;;)
		{
			lua_rawgeti(params.L,-1,++idx);
			if (lua_type(params.L,-1)==LUA_TNIL)
			{
				lua_pop(params.L, 1);
				break;
			}
			else
			{
				if (lua_type(params.L,-1)!=LUA_TTABLE) goto err2;

				lua_getfield(params.L,-1, "type");
				if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err3;
				type = (uint8_t)lua_tointeger(params.L,-1);
				lua_pop(params.L, 1);

				lua_getfield(params.L,-1, "next");
				next = lua_type(params.L,-1)==LUA_TNUMBER ? (uint8_t)lua_tointeger(params.L,-1) : IPPROTO_NONE;
				lua_pop(params.L, 1);

				lua_getfield(params.L,-1, "data");
				if (lua_type(params.L,-1)!=LUA_TSTRING) goto err3;
				p=(uint8_t*)lua_tolstring(params.L,-1,&l);
				if (!l || (l+2)>left || ((type==IPPROTO_AH) ? (l<6 || ((l+2) & 3)) : ((l+2) & 7))) goto err3;
				memcpy(data+2,p,l);
				l+=2;
				data[0] = next; // may be overwritten later
				data[1] = (type==IPPROTO_AH) ? (l>>2)-2 : (l>>3)-1;
				if (!preserve_next) *last_proto = type;
				last_proto = data; // first byte of header holds type
				left -= l; data += l; filled += l;
				lua_pop(params.L, 2);
			}
		}
	}
	// set last header proto
	if (!preserve_next) *last_proto = proto;

	*len = filled;
	lua_pop(params.L, 1);
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return true;
err2:
	lua_pop(params.L, 2);
	goto err;
err3:
	lua_pop(params.L, 3);
err:
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return false;
}
bool lua_reconstruct_ip6hdr(int idx, struct ip6_hdr *ip6, size_t *len, uint8_t last_proto, bool preserve_next)
{
	LUA_STACK_GUARD_ENTER(params.L)

	const char *p;
	size_t l;
	if (*len<sizeof(struct ip6_hdr) || lua_type(params.L,idx)!=LUA_TTABLE) return false;

	idx = lua_absindex(params.L, idx);

	lua_getfield(params.L,idx,"ip6_flow");
	ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(lua_type(params.L,-1)==LUA_TNUMBER ? (uint32_t)lua_tolint(params.L,-1) : 0x60000000);
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip6_plen");
	ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons((uint16_t)lua_tointeger(params.L,-1));

	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip6_nxt");
	ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = (uint8_t)lua_tointeger(params.L,-1);
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip6_hlim");
	ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = (uint8_t)lua_tointeger(params.L,-1);
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip6_src");
	if (lua_type(params.L,-1)!=LUA_TSTRING) goto err;
	p = lua_tolstring(params.L,-1,&l);
	if (l!=sizeof(struct in6_addr)) goto err;
	ip6->ip6_src = *(struct in6_addr*)p;
	lua_pop(params.L, 1);
	
	lua_getfield(params.L,idx,"ip6_dst");
	if (lua_type(params.L,-1)!=LUA_TSTRING) goto err;
	p = lua_tolstring(params.L,-1,&l);
	if (l!=sizeof(struct in6_addr)) goto err;
	ip6->ip6_dst = *(struct in6_addr*)p;
	lua_pop(params.L, 1);
	return lua_reconstruct_ip6exthdr(idx, ip6, len, last_proto, preserve_next);
err:
	lua_pop(params.L, 1);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
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

	lua_reconstruct_extract_options(L, 2, NULL, &preserve_next, &last_proto);

	if (!lua_reconstruct_ip6hdr(1,(struct ip6_hdr*)data, &len, last_proto, preserve_next))
		luaL_error(L, "invalid data for ip6hdr");
	lua_pushlstring(params.L,data,len);

	LUA_STACK_GUARD_RETURN(L,1)
}

bool lua_reconstruct_iphdr(int idx, struct ip *ip, size_t *len)
{
	const char *p;
	size_t l, lopt=0;

	LUA_STACK_GUARD_ENTER(params.L)

	if (*len<sizeof(struct ip) || lua_type(params.L,-1)!=LUA_TTABLE) return false;

	ip->ip_v = IPVERSION;

	lua_getfield(params.L,idx,"ip_tos");
	ip->ip_tos = (uint8_t)lua_tointeger(params.L,-1);
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip_len");
	ip->ip_len = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip_id");
	ip->ip_id = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip_off");
	ip->ip_off = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip_ttl");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	ip->ip_ttl = (uint8_t)lua_tointeger(params.L,-1);
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip_p");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	ip->ip_p = (uint8_t)lua_tointeger(params.L,-1);
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip_src");
	if (lua_type(params.L,-1)!=LUA_TSTRING) goto err;
	p = lua_tolstring(params.L,-1,&l);
	if (l!=sizeof(struct in_addr)) goto err;
	ip->ip_src = *(struct in_addr*)p;
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"ip_dst");
	if (lua_type(params.L,-1)!=LUA_TSTRING) goto err;
	p = lua_tolstring(params.L,-1,&l);
	if (l!=sizeof(struct in_addr)) goto err;
	ip->ip_dst = *(struct in_addr*)p;
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"options");
	if (lua_type(params.L,-1)==LUA_TSTRING)
	{
		p = lua_tolstring(params.L,-1,&lopt);
		if (lopt)
		{
			if (lopt>40 || ((sizeof(struct ip) + ((lopt+3)&~3)) > *len)) goto err;
			memcpy(ip+1,p,lopt);
			memset(((uint8_t*)ip) + sizeof(struct ip) + lopt, 0, (4-lopt&3)&3);
			lopt = (lopt+3) & ~3;
		}
	}
	lua_pop(params.L, 1);

	*len = sizeof(struct ip) + lopt;
	ip->ip_hl = *len >> 2;

	ip4_fix_checksum(ip);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return true;
err:
	lua_pop(params.L, 1);
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return false;
}
static int luacall_reconstruct_iphdr(lua_State *L)
{
	lua_check_argc(L,"reconstruct_iphdr",1);

	LUA_STACK_GUARD_ENTER(L)

	char data[60];
	size_t l = sizeof(data);
	if (!lua_reconstruct_iphdr(1,(struct ip*)&data,&l))
		luaL_error(L, "invalid data for iphdr");
	lua_pushlstring(params.L,data,l);

	LUA_STACK_GUARD_RETURN(L,1)
}

static bool lua_reconstruct_tcphdr_options(int idx, struct tcphdr *tcp, size_t *len)
{
	if (*len<sizeof(struct tcphdr)) return false;

	LUA_STACK_GUARD_ENTER(params.L)

	uint8_t filled = sizeof(struct tcphdr);

	lua_getfield(params.L,idx,"options");
	if (lua_type(params.L,-1)==LUA_TTABLE)
	{
		lua_Integer idx=0;
		uint8_t *p, *data = (uint8_t*)(tcp+1);
		size_t l, left;
		uint8_t kind;

	 	left = *len - filled;
		if (left>40) left=40; // max size of tcp options

		for (;;)
		{
			lua_rawgeti(params.L,-1,++idx);
			if (lua_type(params.L,-1)==LUA_TNIL)
			{
				lua_pop(params.L, 1);
				break;
			}
			else
			{
				// uses 'key' (at index -2) and 'value' (at index -1)

				if (!left || lua_type(params.L,-1)!=LUA_TTABLE) goto err2;

				lua_getfield(params.L,-1, "kind");
				if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err3;

				kind = (uint8_t)lua_tointeger(params.L,-1);
				lua_pop(params.L, 1);

				switch(kind)
				{
					case TCP_KIND_END:
						*data = kind; data++; left--; filled++;
						lua_pop(params.L, 1);
						goto end;
					case TCP_KIND_NOOP:
						*data = kind; data++; left--; filled++;
						break;
					default:
						lua_getfield(params.L,-1, "data");
						l = 0;
						p = lua_type(params.L,-1)==LUA_TSTRING ? (uint8_t*)lua_tolstring(params.L,-1,&l) : NULL;
						if ((2+l)>left) goto err3;
						if (p) memcpy(data+2,p,l);
						l+=2;
						data[0] = kind;
						data[1] = (uint8_t)l;
						left -= l;
						data += l;
						filled += l;
						lua_pop(params.L, 1);
				}
				lua_pop(params.L, 1);
			}
		}
end:
		while(filled & 3)
		{
			if (!left) goto err1;
			*data = TCP_KIND_NOOP; data++; left--; filled++;
		}
	}

	tcp->th_off = filled>>2;
	*len = filled;

	lua_pop(params.L, 1);
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return true;
err1:
	lua_pop(params.L, 1);
	goto err;
err2:
	lua_pop(params.L, 2);
	goto err;
err3:
	lua_pop(params.L, 3);
err:
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return false;
}
bool lua_reconstruct_tcphdr(int idx, struct tcphdr *tcp, size_t *len)
{
	if (*len<sizeof(struct tcphdr) || lua_type(params.L,-1)!=LUA_TTABLE) return false;

	LUA_STACK_GUARD_ENTER(params.L)

	idx = lua_absindex(params.L, idx);

	lua_getfield(params.L,idx,"th_sport");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_sport = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"th_dport");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_dport = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"th_seq");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_seq = htonl((uint32_t)lua_tolint(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"th_ack");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_ack = htonl((uint32_t)lua_tolint(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"th_x2");
	tcp->th_x2 = (uint8_t)lua_tointeger(params.L,-1);
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"th_flags");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_flags = (uint8_t)lua_tointeger(params.L,-1);
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"th_win");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	tcp->th_win = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"th_sum");
	tcp->th_sum = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"th_urp");
	tcp->th_urp = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	tcp->th_off = 5;

	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return lua_reconstruct_tcphdr_options(idx, tcp, len);
err:
	lua_pop(params.L, 1);
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return false;
}
static int luacall_reconstruct_tcphdr(lua_State *L)
{
	lua_check_argc(L,"reconstruct_tcphdr",1);

	LUA_STACK_GUARD_ENTER(L)

	char data[60];
	size_t len=sizeof(data);
	if (!lua_reconstruct_tcphdr(1,(struct tcphdr*)data,&len))
		luaL_error(L, "invalid data for tcphdr");
	lua_pushlstring(params.L,data,len);

	LUA_STACK_GUARD_RETURN(L,1)
}

bool lua_reconstruct_udphdr(int idx, struct udphdr *udp)
{
	if (lua_type(params.L,-1)!=LUA_TTABLE) return false;

	LUA_STACK_GUARD_ENTER(params.L)

	lua_getfield(params.L,idx,"uh_sport");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	udp->uh_sport = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"uh_dport");
	if (lua_type(params.L,-1)!=LUA_TNUMBER) goto err;
	udp->uh_dport = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"uh_ulen");
	udp->uh_ulen = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"uh_sum");
	udp->uh_sum = htons((uint16_t)lua_tointeger(params.L,-1));
	lua_pop(params.L, 1);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return true;
err:
	lua_pop(params.L, 1);
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return false;
}
static int luacall_reconstruct_udphdr(lua_State *L)
{
	LUA_STACK_GUARD_ENTER(L)

	lua_check_argc(L,"reconstruct_udphdr",1);
	struct udphdr udp;
	if (!lua_reconstruct_udphdr(1,&udp))
		luaL_error(L, "invalid data for udphdr");
	lua_pushlstring(params.L,(char*)&udp,sizeof(udp));

	LUA_STACK_GUARD_RETURN(L,1)
}

uint8_t lua_ip6_l4proto_from_dissect(int idx)
{
	int type;

	lua_getfield(params.L,idx,"tcp");
	type=lua_type(params.L,-1);
	lua_pop(params.L,1);
	if (type==LUA_TTABLE) return IPPROTO_TCP;

	lua_getfield(params.L,idx,"udp");
	type=lua_type(params.L,-1);
	lua_pop(params.L,1);
	return type==LUA_TTABLE ? IPPROTO_UDP : IPPROTO_NONE;
}

bool lua_reconstruct_dissect(int idx, uint8_t *buf, size_t *len, bool badsum, bool ip6_preserve_next)
{
	uint8_t *data = buf;
	size_t l,lpayload,l3,left = *len;
	struct ip *ip=NULL;
	struct ip6_hdr *ip6=NULL;
	struct tcphdr *tcp=NULL;
	struct udphdr *udp=NULL;
	const char *p;

	LUA_STACK_GUARD_ENTER(params.L)

	idx = lua_absindex(params.L, idx);

	lua_getfield(params.L,idx,"ip");
	l = left;
	if (lua_type(params.L,-1)==LUA_TTABLE)
	{
		ip = (struct ip*)data;
		if (!lua_reconstruct_iphdr(-1, ip, &l))
		{
			DLOG_ERR("reconstruct_dissect: bad ip\n");
			goto err;
		}
		ip4_fix_checksum(ip);
	}
	else
	{
		lua_pop(params.L, 1);
		lua_getfield(params.L,idx,"ip6");
		if (lua_type(params.L,-1)!=LUA_TTABLE) goto err;
		ip6 = (struct ip6_hdr*)data;
		if (!lua_reconstruct_ip6hdr(-1, ip6, &l, lua_ip6_l4proto_from_dissect(idx), ip6_preserve_next))
		{
			DLOG_ERR("reconstruct_dissect: bad ip6\n");
			goto err;
		}
	}
	l3=l;
	data+=l; left-=l;
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"tcp");
	l = left;
	if (lua_type(params.L,-1)==LUA_TTABLE)
	{
		tcp = (struct tcphdr*)data;
		if (!lua_reconstruct_tcphdr(-1, tcp, &l))
		{
			DLOG_ERR("reconstruct_dissect: bad tcp\n");
			goto err;
		}
	}
	else
	{
		lua_pop(params.L, 1);
		lua_getfield(params.L,idx,"udp");
		l = sizeof(struct udphdr);
		if (lua_type(params.L,-1)!=LUA_TTABLE || left<l) goto err;
		udp = (struct udphdr*)data;
		if (!lua_reconstruct_udphdr(-1, udp))
		{
			DLOG_ERR("reconstruct_dissect: bad udp\n");
			goto err;
		}
	}
	data+=l; left-=l;
	lua_pop(params.L, 1);

	lua_getfield(params.L,idx,"payload");
	p = lua_tolstring(params.L,-1,&lpayload);
	if (lpayload)
	{
		if (left<lpayload) goto err;
		memcpy(data,p,lpayload);
		data+=lpayload; left-=lpayload;
	}
	lua_pop(params.L, 1);

	l = data-buf;
	if (udp)
	{
		udp->uh_ulen = htons((uint16_t)(lpayload+sizeof(struct udphdr)));
		udp_fix_checksum(udp,l-l3,ip,ip6);
		if (badsum) udp->uh_sum ^= 1 + (random() % 0xFFFF);
	}
	if (tcp)
	{
		tcp_fix_checksum(tcp,l-l3,ip,ip6);
		if (badsum) tcp->th_sum ^= 1 + (random() % 0xFFFF);
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
			if (frag_start>l)
			{
				DLOG_ERR("ipv4 frag : fragment offset is outside of the packet\n");
				goto err;
			}
			if (off) memmove(buf+l3,buf+l3+off,iplen-l3);
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
	
	*len = l;
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return true;
err:
	lua_pop(params.L, 1);
	LUA_STACK_GUARD_LEAVE(params.L, 0)
	return false;
}
static int luacall_reconstruct_dissect(lua_State *L)
{
	// reconstruct_dissect(data, reconstruct_opts)
	lua_check_argc_range(L,"reconstruct_dissect",1,2);

	LUA_STACK_GUARD_ENTER(L)

	uint8_t buf[RECONSTRUCT_MAX_SIZE];
	size_t l = sizeof(buf);

	bool ip6_preserve_next, badsum;
	lua_reconstruct_extract_options(params.L, 2, &badsum, &ip6_preserve_next, NULL);

	if (!lua_reconstruct_dissect(1, buf, &l, badsum, ip6_preserve_next))
		luaL_error(L, "invalid dissect data");
	lua_pushlstring(params.L,(char*)buf,l);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_dissect(lua_State *L)
{
	// dissect(packet_data)
	lua_check_argc(L,"dissect",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (const uint8_t*)luaL_checklstring(L, 1, &len);

	struct dissect dis;
	proto_dissect_l3l4(data, len, &dis);

	lua_push_dissect(&dis);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_csum_ip4_fix(lua_State *L)
{
	// csum_ip4_fix(ip_header) returns ip_header
	lua_check_argc(L,"csum_ip4_fix",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t l;
	const uint8_t *data = (const uint8_t*)luaL_checklstring(L, 1, &l);
	if (l>60 || !proto_check_ipv4(data, l))
		luaL_error(L, "invalid ip header");

	uint8_t data2[60];
	memcpy(data2, data, l);
	ip4_fix_checksum((struct ip*)data2);

	lua_pushlstring(params.L,(char*)data2,l);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_csum_tcp_fix(lua_State *L)
{
	// csum_tcp_fix(ip_header, tcp_header, payload) returns tcp_header
	lua_check_argc(L,"csum_tcp_fix",3);

	LUA_STACK_GUARD_ENTER(L)

	size_t l_ip;
	const uint8_t *b_ip = (const uint8_t*)luaL_checklstring(L, 1, &l_ip);
	const struct ip *ip=NULL;
	const struct ip6_hdr *ip6=NULL;

	if (proto_check_ipv4(b_ip, l_ip))
		ip = (struct ip*)b_ip;
	else if (proto_check_ipv6(b_ip, sizeof(struct ip6_hdr) + ntohs(((struct ip6_hdr*)b_ip)->ip6_ctlun.ip6_un1.ip6_un1_plen)))
		ip6 = (struct ip6_hdr*)b_ip;
	else
		luaL_error(L, "invalid ip header");

	size_t l_tcp;
	const uint8_t *b_tcp = (const uint8_t*)luaL_checklstring(L, 2, &l_tcp);
	if (!proto_check_tcp(b_tcp, l_tcp))
		luaL_error(L, "invalid tcp header");

	size_t l_pl;
	const uint8_t *b_pl = (const uint8_t*)luaL_checklstring(L, 3, &l_pl);

	size_t l_tpl = l_tcp + l_pl;
	uint8_t *tpl = malloc(l_tpl);
	if (!tpl) luaL_error(L, "out of memory");

	memcpy(tpl, b_tcp, l_tcp);
	memcpy(tpl+l_tcp, b_pl, l_pl);
	struct tcphdr *tcp = (struct tcphdr*)tpl;
	tcp_fix_checksum(tcp, l_tpl, ip, ip6);

	lua_pushlstring(L,(char*)tpl,l_tcp);
	free(tpl);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_csum_udp_fix(lua_State *L)
{
	// csum_udp_fix(ip_header, udp_header, payload) returns udp_header
	lua_check_argc(L,"csum_udp_fix",3);

	LUA_STACK_GUARD_ENTER(L)

	size_t l_ip;
	const uint8_t *b_ip = (const uint8_t*)luaL_checklstring(L, 1, &l_ip);
	const struct ip *ip=NULL;
	const struct ip6_hdr *ip6=NULL;

	if (proto_check_ipv4(b_ip, l_ip))
		ip = (struct ip*)b_ip;
	else if (proto_check_ipv6(b_ip, sizeof(struct ip6_hdr) + ntohs(((struct ip6_hdr*)b_ip)->ip6_ctlun.ip6_un1.ip6_un1_plen)))
		ip6 = (struct ip6_hdr*)b_ip;
	else
		luaL_error(L, "invalid ip header");

	size_t l_udp;
	const uint8_t *b_udp = (const uint8_t*)luaL_checklstring(L, 2, &l_udp);
	if (!proto_check_udp(b_udp, ntohs(((struct udphdr*)b_udp)->uh_ulen)))
		luaL_error(L, "invalid udp header");

	size_t l_pl;
	const uint8_t *b_pl = (const uint8_t*)luaL_checklstring(L, 3, &l_pl);

	size_t l_tpl = l_udp + l_pl;
	uint8_t *tpl = malloc(l_tpl);
	if (!tpl) luaL_error(L, "out of memory");

	memcpy(tpl, b_udp, l_udp);
	memcpy(tpl+l_udp, b_pl, l_pl);
	struct udphdr *udp = (struct udphdr*)tpl;
	udp_fix_checksum(udp, l_tpl, ip, ip6);

	lua_pushlstring(L,(char*)tpl,l_udp);
	free(tpl);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_ntop(lua_State *L)
{
	size_t l;
	const char *p;
	char s[40];
	int af=0;

	lua_check_argc(L,"ntop",1);

	LUA_STACK_GUARD_ENTER(L)

	p=luaL_checklstring(L,1,&l);
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
	if (!inet_ntop(af,p,s,sizeof(s)))
		luaL_error(L, "inet_ntop error");
	lua_pushstring(L,s);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_pton(lua_State *L)
{
	const char *p;
	char s[sizeof(struct in6_addr)];

	lua_check_argc(L,"pton",1);

	LUA_STACK_GUARD_ENTER(L)

	p=luaL_checkstring(L,1);
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

	data=(uint8_t*)luaL_checklstring(L,1,&len);
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
	// rawsend(data, rawsend_opts, reconstruct_opts)
	lua_check_argc_range(L,"rawsend_dissect",1,3);

	LUA_STACK_GUARD_ENTER(L)

	uint8_t buf[RECONSTRUCT_MAX_SIZE];
	size_t len=sizeof(buf);
	const char *ifout;
	int repeats;
	uint32_t fwmark;
	sockaddr_in46 sa;
	bool b, badsum, ip6_preserve_next;

	luaL_checktype(L,1,LUA_TTABLE);
	lua_rawsend_extract_options(L,2, &repeats, &fwmark, &ifout);
	lua_reconstruct_extract_options(params.L, 3, &badsum, &ip6_preserve_next, NULL);

	if (!lua_reconstruct_dissect(1, buf, &len, badsum, ip6_preserve_next))
		luaL_error(L, "invalid dissect data");

	if (!extract_dst(buf, len, (struct sockaddr*)&sa))
		luaL_error(L, "bad ip4/ip6 header");
	DLOG("rawsend_dissect repeats=%d size=%zu badsum=%u ifout=%s fwmark=%08X\n", repeats,len,badsum,ifout ? ifout : "",fwmark);
	b = rawsend_rep(repeats, (struct sockaddr*)&sa, fwmark, ifout, buf, len);
	lua_pushboolean(L, b);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_resolve_pos(lua_State *L)
{
	// resolve_pos(blob,l7payload_type,marker[,zero_based_pos])
	lua_check_argc_range(L,"resolve_pos",3,4);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	const char *sl7payload = luaL_checkstring(L,2);
	const char *smarker = luaL_checkstring(L,3);
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
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	const char *sl7payload = luaL_checkstring(L,2);
	const char *smarkers = luaL_checkstring(L,3);
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
	for(i=0;i<ctpos;i++) lua_pushi_int(i+1,pos[i]+!bZeroBased);

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
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	const char *sl7payload = luaL_checkstring(L,2);
	const char *smarkers = luaL_checkstring(L,3);
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
	lua_pushi_int(1,pos[0]+!bZeroBased);
	lua_pushi_int(2,pos[1]+!bZeroBased);

	LUA_STACK_GUARD_RETURN(L,1)
}

static int luacall_tls_record_is_tls_client_hello(lua_State *L)
{
	// (blob,partialOK)
	lua_check_argc_range(L,"tls_record_is_tls_client_hello",1,2);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	bool bPartialOK = argc>=2 && lua_toboolean(L,2);

	lua_pushboolean(L,IsTLSClientHello(data,len,bPartialOK));

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_record_is_tls_server_hello(lua_State *L)
{
	// (blob,partialOK)
	lua_check_argc_range(L,"tls_record_is_tls_server_hello",1,2);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	bool bPartialOK = argc>=2 && lua_toboolean(L,2);

	lua_pushboolean(L,IsTLSServerHello(data,len,bPartialOK));

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_handshake_is_tls_client_hello(lua_State *L)
{
	// (blob,partialOK)
	lua_check_argc_range(L,"tls_handshake_is_tls_client_hello",1,2);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	bool bPartialOK = argc>=2 && lua_toboolean(L,2);

	lua_pushboolean(L,IsTLSHandshakeClientHello(data,len,bPartialOK));

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_handshake_is_tls_server_hello(lua_State *L)
{
	// (blob,partialOK)
	lua_check_argc_range(L,"tls_handshake_is_tls_server_hello",1,2);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	bool bPartialOK = argc>=2 && lua_toboolean(L,2);

	lua_pushboolean(L,IsTLSHandshakeServerHello(data,len,bPartialOK));

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_record_find_ext(lua_State *L)
{
	// (blob,type,partialOK)
	lua_check_argc_range(L,"tls_record_find_ext",2,3);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t len, len_ext;
	const uint8_t *ext, *data = (uint8_t*)luaL_checklstring(L,1,&len);
	luaL_checktype(L,2,LUA_TNUMBER);
	uint16_t type = (uint16_t)lua_tointeger(L,2);
	bool bPartialOK = argc>=3 && lua_toboolean(L,3);

	bool b = TLSFindExt(data, len, type, &ext, &len_ext, bPartialOK);
	lua_pushinteger(L,b ? ext-data+1 : 0);
	lua_pushinteger(L,b ? len_ext : 0);

	LUA_STACK_GUARD_RETURN(L,2)
}
static int luacall_tls_handshake_find_ext(lua_State *L)
{
	// (blob,type,partialOK)
	lua_check_argc_range(L,"tls_handshake_find_ext",2,3);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);
	size_t len, len_ext;
	const uint8_t *ext, *data = (uint8_t*)luaL_checklstring(L,1,&len);
	luaL_checktype(L,2,LUA_TNUMBER);
	uint16_t type = (uint16_t)lua_tointeger(L,2);
	bool bPartialOK = argc>=3 && lua_toboolean(L,3);

	bool b = TLSFindExtInHandshake(data, len, type, &ext, &len_ext, bPartialOK);
	lua_pushinteger(L,b ? ext-data+1 : 0);
	lua_pushinteger(L,b ? len_ext : 0);

	LUA_STACK_GUARD_RETURN(L,2)
}
static int luacall_tls_record_find_extlen(lua_State *L)
{
	// (blob)
	lua_check_argc(L,"tls_record_find_extlen",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len, offset;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);

	bool b = TLSFindExtLen(data, len, &offset);
	lua_pushinteger(L,b ? offset+1 : 0);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_handshake_find_extlen(lua_State *L)
{
	// (blob)
	lua_check_argc(L,"tls_handshake_find_extlen",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len, offset;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);

	bool b = TLSFindExtLenOffsetInHandshake(data, len, &offset);
	lua_pushinteger(L,b ? offset+1 : 0);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_record_len(lua_State *L)
{
	// (blob)
	lua_check_argc(L,"tls_record_len",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	lua_pushinteger(L,IsTLSHello(data,len,0,true) ? TLSRecordLen(data) : 0);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_record_data_len(lua_State *L)
{
	// (blob)
	lua_check_argc(L,"tls_record_data_len",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	lua_pushinteger(L,IsTLSHello(data,len,0,true) ? TLSRecordDataLen(data) : 0);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_record_is_full(lua_State *L)
{
	// (blob)
	lua_check_argc(L,"tls_record_is_full",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	lua_pushboolean(L,IsTLSHello(data,len,0,true) && IsTLSRecordFull(data,len) );

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_handshake_len(lua_State *L)
{
	// (blob)
	lua_check_argc(L,"tls_handshake_len",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	lua_pushinteger(L,IsTLSHandshakeHello(data,len,0,true) ? TLSHandshakeLen(data) : 0);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_handshake_data_len(lua_State *L)
{
	// (blob)
	lua_check_argc(L,"tls_handshake_data_len",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	lua_pushinteger(L,IsTLSHandshakeHello(data,len,0,true) ? TLSHandshakeDataLen(data) : 0);

	LUA_STACK_GUARD_RETURN(L,1)
}
static int luacall_tls_handshake_is_full(lua_State *L)
{
	// (blob)
	lua_check_argc(L,"tls_handshake_is_full",1);

	LUA_STACK_GUARD_ENTER(L)

	size_t len;
	const uint8_t *data = (uint8_t*)luaL_checklstring(L,1,&len);
	lua_pushboolean(L,IsTLSHandshakeFull(data,len));

	LUA_STACK_GUARD_RETURN(L,1)
}


static int luacall_tls_mod(lua_State *L)
{
	// (blob, modlist, payload)
	lua_check_argc_range(L,"tls_mod",2,3);

	LUA_STACK_GUARD_ENTER(L)

	int argc=lua_gettop(L);

	size_t fake_tls_len;
	bool bRes;
	const uint8_t *fake_tls = (uint8_t*)luaL_checklstring(L,1,&fake_tls_len);
	const char *modlist = luaL_checkstring(L,2);

	size_t payload_len = 0;
	const uint8_t *payload = NULL;
	if (argc>=3 && lua_type(L,3)!=LUA_TNIL)
		payload = (uint8_t*)luaL_checklstring(L,3,&payload_len);

	struct fake_tls_mod mod;
	if (!TLSMod_parse_list(modlist, &mod))
		luaL_error(L, "invalid tls mod list : '%s'", modlist);

	if (mod.mod)
	{
		size_t newlen = fake_tls_len, maxlen = fake_tls_len + sizeof(mod.sni) + 4;
		uint8_t *newtls = malloc(maxlen);
		if (!newtls) luaL_error(L, "out of memory");

		memcpy(newtls, fake_tls, newlen);
		bRes = TLSMod(&mod, payload, payload_len, newtls, &newlen, maxlen);
		lua_pushlstring(L,(char*)newtls,newlen);

		free(newtls);
	}
	else
	{
		// no mod. push it back
		lua_pushlstring(L,(char*)fake_tls,fake_tls_len);
		bRes = true;
	}
	lua_pushboolean(L, bRes);

	LUA_STACK_GUARD_RETURN(L,2)
}


// ----------------------------------------


void lua_shutdown()
{
	if (params.L)
	{
		DLOG("LUA SHUTDOWN\n");
		// conntrack holds lua state. must clear it before lua shoudown
		ConntrackPoolDestroy(&params.conntrack);
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
static int lua_panic (lua_State *L)
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

bool lua_test_init_script_files(void)
{
	struct str_list *str;
	LIST_FOREACH(str, &params.lua_init_scripts, next)
	{
		if (str->str[0]=='@' && !file_open_test(str->str+1, O_RDONLY))
		{
			DLOG_ERR("LUA file '%s' not accessible\n",str->str+1);
			return false;
		}
	}
	return true;
}

static bool lua_init_scripts(void)
{
	struct str_list *str;
	int status;

	LIST_FOREACH(str, &params.lua_init_scripts, next)
	{
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
		if ((status = str->str[0]=='@' ? luaL_dofile(params.L, str->str+1) : luaL_dostring(params.L, str->str)))
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

		{"DEFAULT_MSS",DEFAULT_MSS},

		{"IP_BASE_LEN",sizeof(struct ip)},
		{"IP6_BASE_LEN",sizeof(struct ip6_hdr)},
		{"TCP_BASE_LEN",sizeof(struct tcphdr)},
		{"UDP_BASE_LEN",sizeof(struct udphdr)},

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
		{"IPTOS_DSCP_MASK",0xF0},
		{"IP6F_MORE_FRAG",0x0001}, // in ip6.h it's defined depending of machine byte order

		{"IPPROTO_IP",IPPROTO_IP},
		{"IPPROTO_IPV6",IPPROTO_IPV6},
		{"IPPROTO_ICMP",IPPROTO_ICMP},
		{"IPPROTO_TCP",IPPROTO_TCP},
		{"IPPROTO_UDP",IPPROTO_UDP},
		{"IPPROTO_ICMPV6",IPPROTO_ICMPV6},
		{"IPPROTO_HOPOPTS",IPPROTO_HOPOPTS},
		{"IPPROTO_ROUTING",IPPROTO_ROUTING},
		{"IPPROTO_FRAGMENT",IPPROTO_FRAGMENT},
		{"IPPROTO_AH",IPPROTO_AH},
		{"IPPROTO_ESP",IPPROTO_ESP},
		{"IPPROTO_DSTOPTS",IPPROTO_DSTOPTS},
		{"IPPROTO_MH",IPPROTO_MH},
		{"IPPROTO_HIP",IPPROTO_HIP},
		{"IPPROTO_SHIM6",IPPROTO_SHIM6},
		{"IPPROTO_NONE",IPPROTO_NONE}
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
		{"bitxor",luacall_bitxor},
		{"bitget",luacall_bitget},
		{"bitset",luacall_bitset},
		{"bitnot",luacall_bitnot},

		// WARNING : lua 5.1 and luajit does not correctly implement integers. they seem to be stored as float which can't hold 64-bit.
		// convert part of the blob (string) to number
		{"u8",luacall_u8},
		{"u16",luacall_u16},
		{"u24",luacall_u24},
		{"u32",luacall_u32},
		// add any number of arguments as they would be unsigned int of specific size
		{"u8add",luacall_u8add},
		{"u16add",luacall_u16add},
		{"u24add",luacall_u24add},
		{"u32add",luacall_u32add},
		// convert number to blob (string) - big endian
		{"bu8",luacall_bu8},
		{"bu16",luacall_bu16},
		{"bu24",luacall_bu24},
		{"bu32",luacall_bu32},
		// swap byte order
		{"swap16",luacall_swap16},
		{"swap32",luacall_swap32},

		// integer division
		{"divint",luacall_divint},

		// hacky function, write to immutable strings
		{"memcpy",luacall_memcpy},

		// random blob generation
		{"brandom",luacall_brandom},
		{"brandom_az",luacall_brandom_az},
		{"brandom_az09",luacall_brandom_az09},

		// crypto
		{"bcryptorandom",luacall_bcryptorandom},
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
		{"getpid",luacall_getpid},
		{"gettid",luacall_gettid},

		// convert table representation to blob or vise versa
		{"reconstruct_tcphdr",luacall_reconstruct_tcphdr},
		{"reconstruct_udphdr",luacall_reconstruct_udphdr},
		{"reconstruct_ip6hdr",luacall_reconstruct_ip6hdr},
		{"reconstruct_iphdr",luacall_reconstruct_iphdr},
		{"reconstruct_dissect",luacall_reconstruct_dissect},
		{"dissect",luacall_dissect},
		{"csum_ip4_fix",luacall_csum_ip4_fix},
		{"csum_tcp_fix",luacall_csum_tcp_fix},
		{"csum_udp_fix",luacall_csum_udp_fix},

		// send packets
		{"rawsend",luacall_rawsend},
		{"rawsend_dissect",luacall_rawsend_dissect},

		// resolve position markers in any supported payload
		{"resolve_pos",luacall_resolve_pos},
		{"resolve_multi_pos",luacall_resolve_multi_pos},
		{"resolve_range",luacall_resolve_range},

		// tls parse functions
		{"tls_record_is_tls_client_hello",luacall_tls_record_is_tls_client_hello},
		{"tls_record_is_tls_server_hello",luacall_tls_record_is_tls_server_hello},
		{"tls_record_find_ext",luacall_tls_record_find_ext},
		{"tls_record_find_extlen",luacall_tls_record_find_extlen},
		{"tls_record_len",luacall_tls_record_len},
		{"tls_record_data_len",luacall_tls_record_data_len},
		{"tls_record_is_full",luacall_tls_record_is_full},
		{"tls_handshake_is_tls_client_hello",luacall_tls_handshake_is_tls_client_hello},
		{"tls_handshake_is_tls_server_hello",luacall_tls_handshake_is_tls_server_hello},
		{"tls_handshake_find_ext",luacall_tls_handshake_find_ext},
		{"tls_handshake_find_extlen",luacall_tls_handshake_find_extlen},
		{"tls_handshake_len",luacall_tls_handshake_len},
		{"tls_handshake_data_len",luacall_tls_handshake_data_len},
		{"tls_handshake_is_full",luacall_tls_handshake_is_full},
		{"tls_mod",luacall_tls_mod}
	};
	for(int i=0;i<(sizeof(lfunc)/sizeof(*lfunc));i++)
		lua_register(params.L,lfunc[i].name,lfunc[i].f);

	LUA_STACK_GUARD_LEAVE(params.L, 0)
}

bool lua_init(void)
{
	DLOG("\nLUA INIT\n");

	if (!lua_basic_init()) return false;
	lua_sec_harden();
	lua_init_blobs();
	lua_init_const();
	lua_init_functions();
	if (!lua_init_scripts()) goto err;
	if (!lua_desync_functions_exist()) goto err;

	DLOG("LUA INIT DONE\n\n");

	return true;
err:
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
