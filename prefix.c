#include "prefix.h"

USHORT htons(USHORT v)
{
	return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF);
}

ULONG htonl(ULONG value)
{

	return (((value & 0xff000000) >> 24) | ((value & 0x00ff0000) >> 8) | ((value & 0x0000ff00) << 8) | ((value & 0x000000ff) << 24));

}

PCHAR htona(SOCKADDR_IN addr)
{
	PCHAR pAddrStr = (PCHAR)ExAllocatePool(PagedPool, 0x20);
	if (pAddrStr == NULL)
	{
		return NULL;
	}


	sprintf(
		pAddrStr,
		"%d.%d.%d.%d",
		addr.sin_addr.S_un.S_un_b.s_b1,
		addr.sin_addr.S_un.S_un_b.s_b2,
		addr.sin_addr.S_un.S_un_b.s_b3,
		addr.sin_addr.S_un.S_un_b.s_b4);
	return pAddrStr;
}