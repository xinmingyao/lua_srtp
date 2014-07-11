#include "lua_srtp.h"
#include "lua.h"
#include "lauxlib.h"
#include "assert.h"
#include "crypto_math.h"
#include <string.h>
#define false 0
#define true 1
static int
configure_srtp_session(srtp_t *session, uint8_t * key,enum transmission_type type);

static int
lsrtp_init(lua_State *L){
  int res = srtp_init();
  printf("init srtp:%d\n",res);
  return 0;
}
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
  char * send_key = lua_touserdata(L,2);
  char * receiving_key = lua_touserdata(L,3);


  printf("set master key/salt to %s/", octet_string_hex_string(send_key, 16));
  printf("%s\n", octet_string_hex_string(send_key+16, 14));

  printf("set master key/salt to %s/", octet_string_hex_string(receiving_key, 16));
  printf("%s\n", octet_string_hex_string(receiving_key+16, 14));

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
  int len = luaL_checkinteger(L,3);
  int res = srtp_protect(srtp->send_session,buffer,&len);
  if(res == 0){
    lua_pushboolean(L,true);
    lua_pushinteger(L,len);
    return 2;
  }else{
    printf ("protected rtp error:%d\n",res);
    lua_pushboolean(L,false);
    return 1;
  }
}


static int
lprotect_rtcp(lua_State *L){
  return luaL_error(L, "rtcp not support!");
}


static int
lunprotect_rtp(lua_State *L){
  struct lua_srtp  * srtp = lua_touserdata(L,1);
  void * buffer = lua_touserdata(L,2);
  int len = luaL_checkinteger(L,3);
  int res = srtp_unprotect(srtp->receive_session,buffer,&len);
  if(res == 0){
    lua_pushboolean(L,true);
    lua_pushinteger(L,len);
    return 2;
  }else{
    printf ("unprotected rtp error:%d\n",res);
    lua_pushboolean(L,false);
    return 1;
  }
}



static int
lunprotect_rtcp(lua_State *L){
  return luaL_error(L, "rtcp not support!");
}

static int lunpack_rtp(lua_State *L){
  rtp_msg_t * message = lua_touserdata(L,1);
  int len = luaL_checkinteger(L,2) - sizeof(srtp_hdr_t);
  char * msg = malloc(len);
  memcpy(msg,message->body,len);
  lua_pushlightuserdata(L,msg);
  lua_pushinteger(L,len);
  lua_pushinteger(L,ntohs(message->header.ssrc));
  lua_pushinteger(L,ntohs(message->header.ts));
  lua_pushinteger(L,ntohs(message->header.seq));    
  free(message);
  return 5;//msg,sz,ssrc,ts,seq
}
static int lpack_rtp(lua_State *L){//msg,sz,ssrc,ts,seq|str,ssrc,ts,seq
  size_t len = 0;
  int type = lua_type(L,1);
  int next = 2;
  char * data;
  if (type == LUA_TSTRING){
    data = luaL_checklstring(L, 1, &len);
  }else{
    data = lua_touserdata(L,1);
    len = luaL_checkinteger(L,2);
    next ++;
  }
  int ssrc = luaL_checkinteger(L,next);
  next++;
  uint16_t seq = luaL_checkinteger(L,next);
  next++;
  uint32_t ts = luaL_checkinteger(L,next);
  rtp_msg_t * message = malloc(sizeof(*message));
  message->header.ssrc    = ssrc;
  message->header.ts      = ts;
  message->header.seq     = seq;
  message->header.m       = 0;
  message->header.pt      = 0x100;
  message->header.version = 2;
  message->header.p       = 0;
  message->header.x       = 0;
  message->header.cc      = 0;
  assert(len<RTP_MAX_BUF_LEN);
  memcpy(message->body,data,len);
  if (type != LUA_TSTRING){
    free(data);
  }
  lua_pushlightuserdata(L, message);
  lua_pushinteger(L, (int)(sizeof(srtp_hdr_t)+len));  
  return 2;
}



SRTP_API
int
luaopen_lua_srtp(lua_State *L) {
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
    { "pack_rtp",lpack_rtp},
    { "unpack_rtp",lunpack_rtp},
    { "srtp_init",lsrtp_init},
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
    printf("create srtp error:%d!\n",res);
  }
  return res!=0? false:true;
}
