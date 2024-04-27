#pragma once
#include "global.hpp"

typedef struct _CSR_PROCESS
{
	struct _CLIENT_ID ClientId; // 0x0
	struct _LIST_ENTRY ListLink; // 0x10
	struct _LIST_ENTRY ThreadList; // 0x20
	// ...
} CSR_PROCESS, * PCSR_PROCESS;

NTSTATUS WalkCsrss();
NTSTATUS WalkCsrssInternal(PEPROCESS Process);
VOID EnumCsrssProcessList(PCSR_PROCESS CsrProcessList);