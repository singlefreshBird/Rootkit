#pragma once
#include "prefix.h"



typedef struct _HOOK_IO_COMPLETION {
	PIO_COMPLETION_ROUTINE OriginalCompletion;
	PVOID OriginalContext;
	BOOLEAN bShouldInvolve;
	PKPROCESS pcb;
}HOOK_IO_COMPLETION,* PHOOK_IO_COMPLETION;

typedef struct _NET_INFO
{
	USHORT Type;            		// +0x00
	USHORT lPort;           		// +0x02
	ULONG lHost;            		// +0x04
	char Reserved1[0x16];   		// +0x08
	USHORT rPort;           		// +0x1E
	ULONG rHost;            		// +0x20
	char Reserved2[0x14];   		// +0x24
}NET_INFO, * PNET_INFO;       	// Total:0x38

typedef struct _PROC_INFO {
	ULONG Reserved1[3];				// +0x00
	ULONG OwnerPid;					// +0x0C
	LARGE_INTEGER CreateTimestamp;	// +0x10
	ULONGLONG OwningModuleInfo;		// +0x18
}PROC_INFO, * PPROC_INFO;				// Total:0x20

typedef struct _STATE_INFO
{
	ULONG State;						// +0x00
	ULONG Reserved1;					// +0x04
	LARGE_INTEGER CreateTimestamp;	// +0x08
}STATE_INFO, * PSTATE_INFO;			// Total:0x10

// nsiproxy»º³åÇøinBuffer²¼¾Ö£º
typedef struct _MIB_PARAMX32
{
	ULONG Unk_0;						// +0x00
	ULONG Unk_1;						// +0x04
	ULONG* POINTER_32 ModuleId;		// +0x08
	ULONG dwType;					// +0x0C
	ULONG Unk_2;						// +0x10
	ULONG Unk_3;						// +0x14
	VOID* POINTER_32 NetInfo;			// +0x18
	ULONG NetInfoSize;				// +0x1C
	VOID* POINTER_32 outBuffer;		// +0x20
	ULONG outBufferSize;				// +0x24
	VOID* POINTER_32 StateInfo;		// +0x28
	ULONG StateInfoSize;				// +0x2C
	VOID* POINTER_32 ProcInfo;		// +0x30
	ULONG ProcInfoSize;				// +0x34
	ULONG ConnectCounts;				// +0x38
}MIB_PARAMX32, * PMIB_PARAMX32;		// Total:0x3C

typedef struct _MIB_PARAMX64
{
	ULONG64 Unk_0;					// +0x00
	ULONG* ModuleId;					// +0x08
	ULONG64 dwType;					// +0x10
	ULONG64 Unk_2;					// +0x18
	ULONG64 Unk_3;					// +0x20
	PVOID NetInfo;					// +0x28
	ULONG64 NetInfoSize;				// +0x30
	PVOID outBuffer;					// +0x38
	ULONG64 outBufferSize;			// +0x40
	PVOID StateInfo;					// +0x48
	ULONG64 StateInfoSize;			// +0x50
	PVOID ProcInfo;					// +0x58
	ULONG64 ProcInfoSize;				// +0x60
	ULONG64 ConnectCounts;			// +0x68
}MIB_PARAMX64, * PMIB_PARAMX64;		// Total:0x70


typedef NTSTATUS(*OLDIRPMJDEVICECONTROL)(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
OLDIRPMJDEVICECONTROL OldIrpMjDeviceControl;

PFILE_OBJECT pFile_tcp;
PDEVICE_OBJECT pDev_tcp;
PDRIVER_OBJECT pDrv_tcpip;

PVOID  g_InBuff;
CHAR g_szip[16];
ULONG g_portValue;


NTSTATUS GetIPAndPort();
NTSTATUS InstallTCPHook();