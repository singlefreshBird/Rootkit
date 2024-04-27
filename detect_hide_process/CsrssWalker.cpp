#include "CsrssWalker.h"

NTSTATUS WalkCsrss()
{
	PEPROCESS* eps;
	NTSTATUS ntStatus;
	KAPC_STATE kApcState;

	ntStatus = GetProcessByName(L"csrss.exe", &eps, TRUE);
	if (!NT_SUCCESS(ntStatus)) goto cleanup;

	for (ULONG i = 0; eps[i]; i++)
	{
		KeStackAttachProcess(eps[i], &kApcState);
		ntStatus = WalkCsrssInternal(eps[i]);
		KeUnstackDetachProcess(&kApcState);

		DbgPrint("\n-------------------------------------------------------------------------\n");
	}

cleanup:
	if (eps)
	{
		for (ULONG i = 0; eps[i]; i++) ObDereferenceObject(eps[i]);

		ExFreePoolWithTag(eps, 'PeAr');
	}

	return ntStatus;
}

NTSTATUS WalkCsrssInternal(PEPROCESS Process)
{
#ifdef _AMD64_
	const UCHAR pattern[] = "\x48\x8B\x0D\xCC\xCC\xCC\xCC";
#else
	const UCHAR pattern[] = "\x8B\x0D\xB4\xCC\xCC\xCC\xCC";
#endif

	UNICODE_STRING uszCsrsrv = RTL_CONSTANT_STRING(L"csrsrv.dll");
	PVOID pfnCsrLocateServerThread = NULL;
	PVOID fdPos;
	NTSTATUS ntStatus;
	PVOID pfnCsrExecServerThread = NULL;
	PVOID pCsrsrvBase;
	PCSR_PROCESS* ppCsrProcssList;

	__try 
	{
		do 
		{
			pCsrsrvBase = BBGetUserModule(Process, &uszCsrsrv);
			if (pCsrsrvBase == NULL)
			{
				ntStatus = STATUS_NOT_FOUND;
				break;
			}

			pfnCsrExecServerThread = BBGetModuleExport(pCsrsrvBase, "CsrExecServerThread", Process);
			if (pfnCsrExecServerThread == NULL)
			{
				ntStatus = STATUS_NOT_FOUND;
				break;
			}

			ntStatus = BBSearchPattern(pattern, 0xCC, sizeof(pattern) - 1, pfnCsrExecServerThread, 0x40, &fdPos);
			if (!NT_SUCCESS(ntStatus)) break;

			ProbeForRead(fdPos, sizeof(ULONG), 1);
#ifdef _AMD64_
			ppCsrProcssList = (PCSR_PROCESS*)((PUCHAR)fdPos + *(PULONG)((PUCHAR)fdPos + 3) + sizeof(pattern) - 1);
#else
			ppCsrProcssList = *(PCSR_PROCESS**)((PUCHAR)fdPos + 2);
#endif
			ProbeForRead(ppCsrProcssList, sizeof(PCSR_PROCESS), 1);

			EnumCsrssProcessList(*ppCsrProcssList);
		} while (FALSE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[!] An exception occurred! Exception code = %I32x\n", GetExceptionCode());
	}
	
	return ntStatus;
}

VOID EnumCsrssProcessList(PCSR_PROCESS CsrProcessList)
{
	PEPROCESS pProcess = NULL;
	NTSTATUS ntStatus;
	PUNICODE_STRING uszProcName;
	PLIST_ENTRY pListHdr;
	PLIST_ENTRY pNext;

	__try
	{
		ProbeForRead(CsrProcessList, sizeof(CSR_PROCESS), 1);

		pListHdr = (PLIST_ENTRY)&CsrProcessList->ListLink;
		pNext = pListHdr->Blink;

		while (pListHdr != pNext)
		{
			PCSR_PROCESS pCsrProc = CONTAINING_RECORD(pNext, CSR_PROCESS, ListLink);
			ProbeForRead(pCsrProc, sizeof(CSR_PROCESS), 1);

			ntStatus = PsLookupProcessByProcessId(pCsrProc->ClientId.UniqueProcess, &pProcess);
			if (NT_SUCCESS(ntStatus))
			{
				ntStatus = SeLocateProcessImageName(pProcess, &uszProcName);
				if (NT_SUCCESS(ntStatus))
				{
					DbgPrint("Pid: %x -- %wZ\n",PsGetProcessId(pProcess) ,uszProcName);
					ExFreePool(uszProcName);
				}
				ObDereferenceObject(pProcess);
			}
			
			pNext = pNext->Blink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[!] An exception occurred! Exception code = %I32x\n", GetExceptionCode());
	}

}