#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef LUAJIT
#include <luajit.h>
#else
#include <lua.h>
#endif
#include <lualib.h>
#include <lauxlib.h>

#include "pools.h"
#include "conntrack.h"
#include "darkmagic.h"

#if LUA_VERSION_NUM < 503
#define lua_isinteger lua_isnumber
#endif
#ifndef LUA_UNSIGNED
#define LUA_UNSIGNED uint64_t
#endif

// in old lua integer is 32 bit on 32 bit platforms and 64 bit on 64 bit platforms
#if LUA_VERSION_NUM < 503 && __SIZEOF_POINTER__==4
#define lua_pushlint lua_pushnumber
#define lua_tolint lua_tonumber
#define luaL_checklint luaL_checknumber
#else
#define lua_pushlint lua_pushinteger
#define luaL_checklint luaL_checkinteger
#define lua_tolint lua_tointeger
#endif

// pushing and not popping inside luacall cause memory leak
// these macros ensure correct stack position or throw error if not
#define LUA_STACK_GUARD_ENTER(L) int _lsg=lua_gettop(L);
#define LUA_STACK_GUARD_LEAVE(L,N) if ((_lsg+N)!=lua_gettop(L)) luaL_error(L,"stack guard failure");
#define LUA_STACK_GUARD_RETURN(L,N) LUA_STACK_GUARD_LEAVE(L,N); return N;
#define LUA_STACK_GUARD_UNWIND(L) lua_settop(L,_lsg);

void desync_instance(const char *func, unsigned int dp_n, unsigned int func_n, char *instance, size_t inst_size);

bool lua_test_init_script_files(void);
void lua_req_quit(void);
bool lua_init(void);
void lua_shutdown(void);
void lua_dlog_error(void);
void lua_do_gc(void);

#if LUA_VERSION_NUM < 502
int lua_absindex(lua_State *L, int idx);
#define lua_rawlen lua_objlen
#endif

const char *lua_reqlstring(lua_State *L,int idx,size_t *len);
const char *lua_reqstring(lua_State *L,int idx);

// push - create object and push to the stack
// pushf - create object and set it as a named field of a table already present on the stack
// pushi - create object and set it as a index field of a table already present on the stack
void lua_pushf_nil(lua_State *L, const char *field);
void lua_pushi_nil(lua_State *L, lua_Integer idx);
void lua_pushf_bool(lua_State *L, const char *field, bool b);
void lua_pushi_bool(lua_State *L, lua_Integer idx, bool b);
void lua_pushf_str(lua_State *L, const char *field, const char *str);
void lua_pushi_str(lua_State *L, lua_Integer idx, const char *str);
void lua_pushf_lstr(lua_State *L, const char *field, const char *str, size_t len);
void lua_pushi_lstr(lua_State *L, lua_Integer idx, const char *str, size_t len);
void lua_pushf_int(lua_State *L, const char *field, lua_Integer v);
void lua_pushi_int(lua_State *L, lua_Integer idx, lua_Integer v);
void lua_pushf_lint(lua_State *L, const char *field, int64_t v);
void lua_pushi_lint(lua_State *L, lua_Integer idx, int64_t v);
void lua_pushf_number(lua_State *L, const char *field, lua_Number v);
void lua_pushi_number(lua_State *L, lua_Integer idx, lua_Number v);
void lua_push_raw(lua_State *L, const void *v, size_t l);
void lua_pushf_raw(lua_State *L, const char *field, const void *v, size_t l);
void lua_pushi_raw(lua_State *L, lua_Integer idx, const void *v, size_t l);
void lua_pushf_reg(lua_State *L, const char *field, int ref);
void lua_pushf_lud(lua_State *L, const char *field, void *p);
void lua_pushf_table(lua_State *L, const char *field);
void lua_pushi_table(lua_State *L, lua_Integer idx);

bool lua_push_blob(lua_State *L, int idx_desync, const char *blob);
bool lua_pushf_blob(lua_State *L, int idx_desync, const char *field, const char *blob);

void lua_push_ipaddr(lua_State *L, const struct sockaddr *sa);
void lua_pushf_ipaddr(lua_State *L, const char *field, const struct sockaddr *sa);
void lua_pushi_ipaddr(lua_State *L, lua_Integer idx, const struct sockaddr *sa);
void lua_pushi_str(lua_State *L, lua_Integer idx, const char *str);
void lua_pushf_tcphdr_options(lua_State *L, const struct tcphdr *tcp, size_t len);
void lua_push_tcphdr(lua_State *L, const struct tcphdr *tcp, size_t len);
void lua_pushf_tcphdr(lua_State *L, const struct tcphdr *tcp, size_t len);
void lua_push_udphdr(lua_State *L, const struct udphdr *udp, size_t len);
void lua_pushf_udphdr(lua_State *L, const struct udphdr *udp, size_t len);
void lua_pushf_icmphdr(lua_State *L, const struct icmp46 *icmp, size_t len);
void lua_push_iphdr(lua_State *L, const struct ip *ip, size_t len);
void lua_pushf_iphdr(lua_State *L, const struct ip *ip, size_t len);
void lua_push_ip6hdr(lua_State *L, const struct ip6_hdr *ip6, size_t len);
void lua_pushf_ip6hdr(lua_State *L, const struct ip6_hdr *ip6, size_t len);
void lua_push_dissect(lua_State *L, const struct dissect *dis);
void lua_pushf_dissect(lua_State *L, const struct dissect *dis);
void lua_push_ctrack(lua_State *L, const t_ctrack *ctrack, const t_ctrack_positions *tpos, bool bIncoming);
void lua_pushf_ctrack(lua_State *L, const t_ctrack *ctrack, const t_ctrack_positions *tpos, bool bIncoming);
bool lua_pushf_args(lua_State *L, const struct str2_list_head *args, int idx_desync, bool subst_prefix);
void lua_pushf_pos(lua_State *L, const char *name, const struct packet_pos *pos);
void lua_pushf_range(lua_State *L, const char *name, const struct packet_range *range);
void lua_pushf_global(lua_State *L, const char *field, const char *global);

bool lua_reconstruct_ip6hdr(lua_State *L, int idx, struct ip6_hdr *ip6, size_t *len, uint8_t last_proto, bool preserve_next);
bool lua_reconstruct_iphdr(lua_State *L, int idx, struct ip *ip, size_t *len);
bool lua_reconstruct_tcphdr(lua_State *L, int idx, struct tcphdr *tcp, size_t *len);
bool lua_reconstruct_udphdr(lua_State *L, int idx, struct udphdr *udp);
bool lua_reconstruct_icmphdr(lua_State *L, int idx, struct icmp46 *icmp);
bool lua_reconstruct_dissect(lua_State *L, int idx, uint8_t *buf, size_t *len, bool keepsum, bool badsum, uint8_t last_proto, bool ip6_preserve_next);

struct s_lua_desync_context
{
	unsigned int func_n;
	const char *func, *instance;
	const struct desync_profile *dp;
	const struct dissect *dis;
	t_ctrack *ctrack;
	bool incoming, cancel;
	bool valid;
};
typedef struct s_lua_desync_context t_lua_desync_context;

bool lua_instance_cutoff_check(lua_State *L, const t_lua_desync_context *ctx, bool bIn);
