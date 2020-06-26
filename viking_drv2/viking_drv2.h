/*
CLIENT / DRIVER communication protocol
*/

// #define CTL_CODE( DeviceType, Function, Method, Access ) ( \
//  ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define IOCTL_PRIORITY_BOOSTER_SET_PRIORITY CTL_CODE(VIKINGDRV2_DEVICE, \
0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

#define VIKINGDRV2_DEVICE 0x8000

struct ThreadData {
	ULONG ThreadId;
	int Priority;
};