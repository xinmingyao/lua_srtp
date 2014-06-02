#ifndef lua_srtcp_h
#define lua_srtcp_h
#include "srtp.h"


#if defined(_WIN32)
#include <windows.h>
#define SRTP_API __declspec(dllexport)



#else
#define SRTP_API 
#endif


enum transmission_type{
  SENDING,RECEIVING
};

struct lua_srtp{
  int active;
  srtp_t send_session;
  srtp_t receive_session;
  srtp_t rtcp_send_session;
  srtp_t rtcp_receive_session;
};

#endif
