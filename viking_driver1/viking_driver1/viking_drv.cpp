#include <ntddk.h>
void SampleUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("[VIKING] driver Unload called\n"));
}

extern "C"
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	//variables
	OSVERSIONINFOEXW osVersionInfo;
	NTSTATUS status = STATUS_SUCCESS;

	// code
	DriverObject->DriverUnload = SampleUnload;
	KdPrint(("[VIKING]  driver initialized successfully\n"));
	osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	status = RtlGetVersion((POSVERSIONINFOW)&osVersionInfo);
	NT_ASSERT(NT_SUCCESS(status));
	/*
	typedef struct _OSVERSIONINFOEXW {
	   ULONG  dwOSVersionInfoSize;
	   ULONG  dwMajorVersion;
	   ULONG  dwMinorVersion;
	   ULONG  dwBuildNumber;
	   ULONG  dwPlatformId;
	   WCHAR  szCSDVersion[128];
	  USHORT wServicePackMajor;
	  USHORT wServicePackMinor;
	  USHORT wSuiteMask;
	  UCHAR  wProductType;
	  UCHAR  wReserved;
	}
	*/
	KdPrint(("[VIKING][VERSION] Major   : %u\n", osVersionInfo.dwMajorVersion));
	KdPrint(("[VIKING][VERSION] Minor   : %u\n", osVersionInfo.dwMinorVersion));
	KdPrint(("[VIKING][VERSION] Build   : %u\n", osVersionInfo.dwBuildNumber));
	KdPrint(("[VIKING][VERSION] OS version Info Size   : %u\n", osVersionInfo.dwOSVersionInfoSize));
	KdPrint(("[VIKING][VERSION] Platform ID   : %u\n", osVersionInfo.dwPlatformId));
	KdPrint(("[VIKING][VERSION] CSD Version (SP Level)  : %s\n", osVersionInfo.szCSDVersion));
	KdPrint(("[VIKING][VERSION] wServicePackMajor  : %u\n", osVersionInfo.wServicePackMajor));
	KdPrint(("[VIKING][VERSION] wServicePackMinor  : %u\n", osVersionInfo.wServicePackMinor));
	KdPrint(("[VIKING][VERSION] wSuiteMask  : %u\n", osVersionInfo.wSuiteMask));
	KdPrint(("[VIKING][VERSION] wProductType  : %s\n", osVersionInfo.wProductType));
	KdPrint(("[VIKING][VERSION] wReserved  : %s\n", osVersionInfo.wReserved));

	return STATUS_SUCCESS;
}