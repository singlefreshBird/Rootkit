#include "CsrssWalker.h"

extern"C"
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DrvObj,
	_In_ PUNICODE_STRING RegPath);

VOID DriverUnload(_In_ PDRIVER_OBJECT DrvObj);

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DrvObj,
	_In_ PUNICODE_STRING RegPath)
{
	DrvObj->DriverUnload = DriverUnload;

	return WalkCsrss();
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DrvObj)
{
	
}