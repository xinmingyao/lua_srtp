#include "lua_srtp.h"
#include "lua.h"
#include "lauxlib.h"

#include <string.h>
#define false -1
#define true 0
static int
configure_srtp_session(srtp_t *session, uint8_t * key,enum transmission_type type);

static int
lnew(lua_State *L) {
  struct lua_srtp * lsrtp = lua_newuserdata(L, sizeof(*lsrtp));
  if(!lsrtp){
    return luaL_error(L, "cannot new lua_srtp");
  }
  lsrtp->active = false;
  lsrtp->send_session = NULL;
  lsrtp->receive_session = NULL;
  return 1;	
}

static int
ldestroy(lua_State *L){
  struct lua_srtp  * srtp = lua_touserdata(L,1);
  free(srtp);
  return 0;
}

static int
lset_rtp(lua_State *L){
  struct lua_srtp  * srtp = lua_touserdata(L,1);
  char * send_key = luaL_checkstring(L,2);
  char * receiving_key = luaL_checkstring(L,3);
  if (configure_srtp_session(&srtp->send_session, send_key, SENDING)
      && configure_srtp_session(&srtp->receive_session, receiving_key, RECEIVING)){
    srtp->active = true;
    lua_pushboolean(L,true);
    return 1;
  }
  lua_pushboolean(L,false);
  return 1;
}


static int
lset_rtcp(lua_State *L){
  return luaL_error(L, "rtcp not support!");
}



static int
lprotect_rtp(lua_State *L){
  struct  lua_srtp  * srtp = lua_touserdata(L,1);
  void * buffer = lua_touserdata(L,2);
  int len = lua_checkinteger(L,3);
  int res = srtp_protect(srtp->send_session,buffer,&len);
  if(res == 0){
    lua_pushboolean(L,true);
  }else{
    lua_pushboolean(L,false);
  }
  return 1;
}


static int
lprotect_rtcp(lua_State *L){
  return luaL_error(L, "rtcp not support!");
}


static int
lunprotect_rtp(lua_State *L){
  struct lua_srtp  * srtp = lua_touserdata(L,1);
  void * buffer = lua_touserdata(L,2);
  int len = lua_checkinteger(L,3);
  int res = srtp_unprotect(srtp->send_session,buffer,&len);
  if(res == 0){
    lua_pushboolean(L,true);
  }else{
    lua_pushboolean(L,false);
  }
  return 1;
}



static int
lunprotect_rtcp(lua_State *L){
  return luaL_error(L, "rtcp not support!");
}




SRTP_API
int
lua_open_lua_srtp(lua_State *L) {
  luaL_checkversion(L);
  luaL_Reg l[] = {
    { "new", lnew },
    { "destroy", ldestroy },
    { "set_rtp", lset_rtp },
    { "set_rtcp", lset_rtcp},
    { "protect_rtp", lprotect_rtp},
    { "unprotect_rtp",lunprotect_rtp},
    { "protect_rtcp", lprotect_rtcp},
    { "unprotect_rtcp",lunprotect_rtcp},
    { NULL, NULL },
  };
  luaL_newlib(L,l);
  return 1;
}


static int
configure_srtp_session(srtp_t *session, uint8_t * key,
		       enum transmission_type type) {
  srtp_policy_t policy;
  memset(&policy, 0, sizeof(policy));
  crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
  crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
  if (type == SENDING) {
    policy.ssrc.type = ssrc_any_outbound;
  } else {
    policy.ssrc.type = ssrc_any_inbound;
  }
  policy.ssrc.value = 0;
  policy.window_size = 1024;
  policy.allow_repeat_tx = 1;
  policy.next = NULL;
  policy.key = key;
  int res = srtp_create(session, &policy);
  if(res!=0){
    printf("create srtp error!\n");
  }
  return res;
  //return res!=0? false:true;
}
