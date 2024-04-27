#include "global.hpp"
#include <ntimage.h>

HANDLE GetProcessIdByName(PWCHAR Name, PHANDLE ParentId)
{
	NTSTATUS ntStatus;
	PEPROCESS pProcess = NULL;
	PUNICODE_STRING pImageFileName = NULL;

	if (Name == NULL)
	{
		return NULL;
	}

	for (ULONG i = 5; i < 100000; i++)
	{
		ntStatus = PsLookupProcessByProcessId((HANDLE)i, &pProcess);
		if (NT_SUCCESS(ntStatus))
		{
			ntStatus = SeLocateProcessImageName(pProcess, &pImageFileName);
			if (NT_SUCCESS(ntStatus))
			{
				if (pImageFileName->MaximumLength >= wcslen(Name) * 2 && wcsstr(pImageFileName->Buffer, Name))
				{
					if(ParentId) *ParentId = PsGetProcessInheritedFromUniqueProcessId(pProcess);

					ExFreePool(pImageFileName);
					ObDereferenceObject(pProcess);
					return (HANDLE)i;
				}
				ExFreePool(pImageFileName);
			}

			ObDereferenceObject(pProcess);
		}
	}

	return NULL;
}

NTSTATUS GetProcessByName(PWCHAR Name, PEPROCESS** Process, BOOLEAN FindAll)
{
	NTSTATUS ntStatus;
	PEPROCESS pProcess = NULL;
	PUNICODE_STRING pImageFileName = NULL;
	ULONG id = 0;

	if (Name == NULL)
	{
		return NULL;
	}

	PEPROCESS* result = (PEPROCESS*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PEPROCESS) * 100, 'PeAr');
	if (result == NULL) return NULL;

	RtlZeroMemory(result, sizeof(PEPROCESS) * 100);

	for (ULONG i = 5; i < 100000; i++)
	{
		ntStatus = PsLookupProcessByProcessId((HANDLE)i, &pProcess);
		if (NT_SUCCESS(ntStatus))
		{
			ntStatus = SeLocateProcessImageName(pProcess, &pImageFileName);
			if (NT_SUCCESS(ntStatus))
			{
				if (pImageFileName->MaximumLength >= wcslen(Name) * 2 && wcsstr(pImageFileName->Buffer, Name))
				{
					ExFreePool(pImageFileName);
					if (FindAll)
					{
						if (id >= 100) break;

						result[id++] = pProcess;
						continue;
					}
					else
					{
						result[id++] = pProcess;
						break;
					}
				}

				ExFreePool(pImageFileName);
			}

			ObDereferenceObject(pProcess);
		}
	}
	
	if (id > 0)
	{
		*Process = result;
		return STATUS_SUCCESS;
	}
	else
	{
		ExFreePoolWithTag(result, 'PeAr');
		*Process = NULL;
		return STATUS_NOT_FOUND;
	}
	
}

PVOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName)
{
	ASSERT(pProcess != NULL);
	if (pProcess == NULL)
		return NULL;

	// Protect from UserMode AV
	__try
	{
		LARGE_INTEGER time = { 0 };
		time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

		PPEB pPeb = PsGetProcessPeb(pProcess);
		if (!pPeb)
		{
			DbgPrint("BlackBone: %s: No PEB present. Aborting\n", __FUNCTION__);
			return NULL;
		}

		// Wait for loader a bit
		for (INT i = 0; !pPeb->Ldr && i < 10; i++)
		{
			DbgPrint("BlackBone: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
			KeDelayExecutionThread(KernelMode, TRUE, &time);
		}

		// Still no loader
		if (!pPeb->Ldr)
		{
			DbgPrint("BlackBone: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
			return NULL;
		}

		// Search in InLoadOrderModuleList
		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
			pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
				return pEntry->DllBase;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("BlackBone: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

	return NULL;
}

PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;

	ASSERT(pBase != NULL);
	if (pBase == NULL)
		return NULL;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	// 32 bit image
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	PULONG  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR  pName = NULL;

		// Find by index
		if ((ULONG_PTR)name_ord <= 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}
		// Find by name
		else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			OrdIndex = pAddressOfOrds[i];
		}
		// Weird params
		else
			return NULL;

		if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
			((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

			break;
		}
	}

	return (PVOID)pAddress;
}

NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}