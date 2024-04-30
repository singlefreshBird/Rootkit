#pragma once
#include<ntifs.h>
#include <ntstrsafe.h>

typedef USHORT ADDRESS_FAMILY;

typedef struct in_addr {
	union {
		struct { UCHAR s_b1, s_b2, s_b3, s_b4; } S_un_b;
		struct { USHORT s_w1, s_w2; } S_un_w;
		ULONG S_addr;
	} S_un;
#define s_addr  S_un.S_addr /* can be used for most tcp & ip code */
#define s_host  S_un.S_un_b.s_b2    // host on imp
#define s_net   S_un.S_un_b.s_b1    // network
#define s_imp   S_un.S_un_w.s_w2    // imp
#define s_impno S_un.S_un_b.s_b4    // imp #
#define s_lh    S_un.S_un_b.s_b3    // logical host
} IN_ADDR, * PIN_ADDR, FAR* LPIN_ADDR;

typedef struct sockaddr_in {

#if(_WIN32_WINNT < 0x0600)
	short   sin_family;
#else //(_WIN32_WINNT < 0x0600)
	ADDRESS_FAMILY sin_family;
#endif //(_WIN32_WINNT < 0x0600)

	USHORT sin_port;
	IN_ADDR sin_addr;
	CHAR sin_zero[8];
} SOCKADDR_IN, * PSOCKADDR_IN;

USHORT htons(USHORT v);
ULONG htonl(ULONG value);
PCHAR htona(SOCKADDR_IN addr);