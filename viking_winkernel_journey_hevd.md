# Windows kernel journey - HEVD
1. [Part 1 - setting up the lab](#lab_setup)
2. [Part 2 - getting familiar with HackSys Extreme Vulnerable Driver](#hevd_intro)
3. [Debugging without symbols (PEB)]()

** ############### **

** Disclaimer **

** Why this memo ? It's just some notes / all information gathered during my "diving into the Windows kernel" journey. **

** I put all my copy / paste skill to create this note. Links are provided for more details (original author) about each chapter **

** ############### **

## Part 1 - setting up the lab [](#){name=lab_setup}

[Link](https://hshrzd.wordpress.com/2017/05/28/starting-with-windows-kernel-exploitation-part-1-setting-up-the-lab/)

### Pre-requisite
* Kali Linux – as a host system (you can use anything you like)
* VirtualBox
* 2 Virtual Machines: Windows 7 32 bit (with VirtualBox Guest Additions installed) – one will be used as aDebugger and another as a Debugee
* WinDbg (you can find it in Windows SDK)


### Setting up the Debugger
Once we have WinDbg installed we should add Symbols.
In order to do this, we just need to add an environment variable, to which WinDbg will automatically refer and fill it with the link from where it can download symbols.
Full variable content may look like this (downloaded symbols will be stored in C:\Symbols):

    _NT_SYMBOL_PATH
    SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols

### Setting up the Debugee
We need to enable Debugee to let it be controlled from outside. In order to do this, we are adding one more option in a boot menu.

    bcdedit /debug {current} on

At the end we can see the settings where the debugging interface will be available:

    bcdedit /dbgsettings

### Interconnect Debugger and Debuggee
I use Linux as my host system, so I choose as a pipe name:

    /tmp/vik_pipe

### Testing the connection
Let’s start the Debugger first, run WinDbg, and make it wait for the connection from the Debugee.

    File->Kernel Debug -> COM


## Part 2 - getting familiar with HackSys Extreme Vulnerable Driver [](#){name=hevd_intro}
[Link](https://hshrzd.wordpress.com/2017/06/05/starting-with-windows-kernel-exploitation-part-2/)

### Installing and testing HEVD
HEVD and the dedicated exploits prints a lot of information as DebugStrings. We can watch them from the Debugger machine (using WinDbg) as well as from Debugee machine (using DebugView).

#### Watching the DebugStrings
**On the Debugger:** We need to break the execution of the Debugee in order to get the kd prompt (in WinDbg: Debug -> Break). Then, we enable printing Debug Strings via command:

    ed nt!Kd_Default_Mask 8

After that, we can let the Debugee run further by executing the command:

    g

**On the Debugee:** We need to run DebugView as Administrator. Then we choose from the menu:

    Capture -> Capture Kernel
<u></u>
#### Installing the driver
First, we will download the pre-build package (driver+exploit) on the Debugee (the victim machine), install them and test.
We use OSLoader or the following commands :


**Win7 (nb: spaces are importants) : **

	#register driver
	sc create HEVD type= kernel start= demand error= normal DisplayName= HEVD binpath= c:\dev\HEVD.sys
	#sc description HEVD HEVD
	sc start HEVD
	sc stop HEVD
	# unregister driver:
	sc delete HEVD

**Win10 : **

    sc create hevd binpath="C:\hevd.sys" type=kernel
    net start hevd

**64 bits**

We have to disable security checks and signature verification.
[Link](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)

    bcdedit.exe -set TESTSIGNING ON
    bcdedit.exe /set nointegritychecks on

Then we can load the "HEVD v3.00\driver\vulnerable\x64\HEVD.sys" which is signed.

#### Adding symbols
The precompiled package of HEVD comes with symbols (sdb file) that we can also add to our Debugger. First, let’s stop the Debugee by sending it a break signal, and have a look at the HEVD module, we can set a filter:


    lm m HEV*

We will see, that it does not have any symbols attached. Well, it can be easily fixed. First, turn on noisy symbol in order to print all the information about the paths to which WinDbg referred in search for the symbol. Then, try to reload the symbols:

    !sym noisy
    .reload

After moving the pdb file to the appropriate location on the Debugger machine, reload the symbols again. You can test them by trying to print all the functions from HEVD:

    .reload
    x HEVD!*

#### Testing the exploits
If the exploitation went successful, the requested application (cmd.exe) will be deployed with elevated privileges.

    HackSysEVDExploit.exe -s -c cmd.exe

                    ##     ## ######## ##     ## ########
                    ##     ## ##       ##     ## ##     ##
                    ##     ## ##       ##     ## ##     ##
                    ######### ######   ##     ## ##     ##
                    ##     ## ##        ##   ##  ##     ##
                    ##     ## ##         ## ##   ##     ##
                    ##     ## ########    ###    ########

                  HackSys Extreme Vulnerable Driver Exploits
                         Ashfaq Ansari (@HackSysTeam)
                           ashfaq[at]payatu[dot]com

        [+] Starting Stack Overflow Exploitation
        [+] Creating The Exploit Thread
                [+] Exploit Thread Handle: 0x40
        [+] Setting Thread Priority
                [+] Priority Set To THREAD_PRIORITY_HIGHEST
        [+] Getting Device Driver Handle
                [+] Device Name: \\.\HackSysExtremeVulnerableDriver
                [+] Device Handle: 0x44
        [+] Setting Up Vulnerability Stage
                [+] Allocating Memory For Buffer
                        [+] Memory Allocated: 0x003AFE38
                        [+] Allocation Size: 0x824
                [+] Preparing Buffer Memory Layout
                        [+] RET Value: 0x00D93060
                        [+] RET Address: 0x003B0658
                [+] EoP Payload: 0x00D93060
        [+] Triggering Kernel Stack Overflow
        [+] Completed Stack Overflow Exploitation
        [+] Checking Current Process Privileges
        [+] Trying To Get Process ID Of: csrss.exe
                [+] Process ID Of csrss.exe: 324
        [+] Trying To Open csrss.exe With PROCESS_ALL_ACCESS
                [+] Process Handle Of csrss.exe: 0x40
        [+] Successfully Elevated Current Process Privileges
        [+] Enjoy As SYSTEM [0.000000]s


### Hi driver, let’s talk!
In order to communicate with a driver from user mode we will be sending it IOCTLs – Input-Output controls.

The IOCTL allows us to send from the user land some input buffer to the driver. This is the point from which we can attempt the exploitation.


#### Finding Device name & IOCTLs

Before we try to communicate with a driver, we need to know two things:

  * the device that the driver creates (if it doesn’t create any, we will not be able to communicate)
  * list of IOCTLs (Input-Output Controls) that the driver accepts

The device name is created with this code ([source code](https://raw.githubusercontent.com/hacksysteam/HackSysExtremeVulnerableDriver/master/Driver/HEVD/Windows/HackSysExtremeVulnerableDriver.c)):

    NTSTATUS
    DriverEntry(
        _In_ PDRIVER_OBJECT DriverObject,
        _In_ PUNICODE_STRING RegistryPath
    )
    {
        UINT32 i = 0;
        PDEVICE_OBJECT DeviceObject = NULL;
        NTSTATUS Status = STATUS_UNSUCCESSFUL;
        UNICODE_STRING DeviceName, DosDeviceName = { 0 };
        UNREFERENCED_PARAMETER(RegistryPath);
        PAGED_CODE();
        RtlInitUnicodeString(&DeviceName, L"\\Device\\HackSysExtremeVulnerableDriver");
        RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\HackSysExtremeVulnerableDriver");
        //
        // Create the device
        //
        Status = IoCreateDevice(
            DriverObject,
            0,
            &DeviceName,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,
            &DeviceObject
        );
        ...
     }

We will start from looking at the array of IRPs. The function linked to IRP_MJ_DEVICE_CONTOL will be dispatching IOCTLs sent to the driver.

    //
    // Assign the IRP handlers for Create, Close and Device Control
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

Now, let’s see find the list of IOCTLs. The switch calls a handler function appropriate to handle a particular IOCTL.

    NTSTATUS
    IrpDeviceIoCtlHandler(
        _In_ PDEVICE_OBJECT DeviceObject,
        _In_ PIRP Irp
    )
    {
        ULONG IoControlCode = 0;
        PIO_STACK_LOCATION IrpSp = NULL;
        NTSTATUS Status = STATUS_NOT_SUPPORTED;
    
        UNREFERENCED_PARAMETER(DeviceObject);
        PAGED_CODE();
    
            IrpSp = IoGetCurrentIrpStackLocation(Irp);
        IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    
        if (IrpSp)
        {
            switch (IoControlCode)
            {
            case HEVD_IOCTL_BUFFER_OVERFLOW_STACK:
                DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******\n");
                Status = BufferOverflowStackIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******\n");
                break;
            case HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS:
                DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS ******\n");
                Status = BufferOverflowStackGSIoctlHandler(Irp, IrpSp);
                DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS ******\n");
                break;
    ...
    }

The values of the constants are defined in the header ([source code](https://raw.githubusercontent.com/hacksysteam/HackSysExtremeVulnerableDriver/master/Driver/HEVD/Windows/HackSysExtremeVulnerableDriver.h)) :

    #define HEVD_IOCTL_BUFFER_OVERFLOW_STACK                         IOCTL(0x800)
    #define HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS                      IOCTL(0x801)
    #define HEVD_IOCTL_ARBITRARY_WRITE                               IOCTL(0x802)
    #define HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL                IOCTL(0x803)
    ...

## Debugging without symbols
In this chapter I will only use memory adresses, offset, etc to get information. So I will be able to debug without the PDB file. The main objective ? I want to set a breakpoint so I can debug this driver when the IOCTL (encapsulated in IRP) arrives to the I/O Manager.
Some symbol information appears in the results below because I just want to verify this method is working as expected, but I don't use those symbols for debugging purpose.

### List the HEVD module information
First I want to know where (in memory) is loaded this driver : it starts at 0xfffff80245570000

`kd> lm Dv m hevd`

    Browse full module list
    start             end                 module name
    fffff802`45570000 fffff802`455fc000   HEVD       (deferred)             
        Image path: HEVD.sys
        Image name: HEVD.sys
        Browse all global symbols  functions  data
        Timestamp:        Tue Jul  2 14:18:56 2019 (5D1B4BB0)
        CheckSum:         00012730
        ImageSize:        0008C000
        Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4



### List the HEVD driver object information
Then I want to know where is stored the HEVD driver object : it can be reached at 0xffffe087d4d11b60

`kd> !drvobj hevd` 

    Driver object (ffffe087d4d11b60) is for:
    *** Unable to resolve unqualified symbol in Bp expression 'Displaying '.
     \Driver\HEVD
    
    Driver Extension List: (id , addr)
    
    Device Object list:
    ffffe087d4df1b70 
    

I can get the device object information, so I can get 2 information :
 * the Windows service name : HEVD
 * the DeviceName (which is used by the client to interact with this driver) : HackSysExtremeVulnerableDriver

`kd> !devobj ffffe087d4df1b70`

     Device object (ffffe087d4df1b70) is for:
     HackSysExtremeVulnerableDriver \Driver\HEVD DriverObject ffff978d2c0a42c0
     

### Find the DeviceIoControl handler
I use the nt module and get some information stated below.

`kd> dt nt!_DRIVER_OBJECT 0xffffe087d4d11b60`

       +0x000 Type             : 0n4
       +0x002 Size             : 0n336
       +0x008 DeviceObject     : 0xffffe087`d4df1b70 _DEVICE_OBJECT
       +0x010 Flags            : 0x12
       +0x018 DriverStart      : 0xfffff802`45570000 Void
       +0x020 DriverSize       : 0x8c000
       +0x028 DriverSection    : 0xffffe087`d4c1b400 Void
       +0x030 DriverExtension  : 0xffffe087`d4d11cb0 _DRIVER_EXTENSION
       +0x038 DriverName       : _UNICODE_STRING "\Driver\HEVD"
       +0x048 HardwareDatabase : 0xfffff802`483b08f8 _UNICODE_STRING "\REGISTRY\MACHINE\HARDWARE\DESCRIPTION\SYSTEM"
       +0x050 FastIoDispatch   : (null) 
       +0x058 DriverInit       : 0xfffff802`455fa134     long  HEVD!GsDriverEntry+0
       +0x060 DriverStartIo    : (null) 
       +0x068 DriverUnload     : 0xfffff802`455f5000     void  HEVD!DriverUnloadHandler+0
       +0x070 MajorFunction    : [28] 0xfffff802`455f5058     long  HEVD!IrpCreateCloseHandler+0

The source code of the driver is something like this :

`DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;`

I just want to locate IrpDeviceIoCtlHandler in memory, in order to set a breakpoint.

Here is a good method to get this information [Practical Malware Analysis - Chapter 10 - p218](https://nostarch.com/malware) (slightly modified because I'm on x64 architecture) :

    The entry for MajorFunction in this structure is a pointer to the first entry
    of the major function table. The major function table tells us what is exe-
    cuted when the malicious driver is called from user space. The table has dif-
    ferent functions at each index. Each index represents a different type of
    request, and the indices are found in the file wdm.h and start with IRP_MJ_ .
    For example, if we want to find out which offset in the table is called
    when a user-space application calls DeviceIoControl , we would look for the
    index of IRP_MJ_DEVICE_CONTROL . In this case, IRP_MJ_DEVICE_CONTROL has a value
    of 0xe , and the major function table starts at an offset of 0x070 from the begin-
    ning of the driver object. To find the function that will be called to handle
    the DeviceIoControl request, use the command dd 0xffffe087d4d11b60+0x070+e*8 L1 .
    
    The 0x070 is the offset to the beginning of the table
    0xe is the index of the IRP_MJ_DEVICE_CONTROL
    and it’s multiplied by 8 because each pointer is 8 bytes (because the OS is 64 bits).
    The L2 argument specifies that we want to see only two DWORD of output.

I can confirm the values of IRP indexes by looking at the wdm.h file :
[Link](https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-headers/ddk/include/ddk/wdm.h#L5477)

    #define IRP_MJ_CREATE                     0x00
    #define IRP_MJ_CREATE_NAMED_PIPE          0x01
    #define IRP_MJ_CLOSE                      0x02
    #define IRP_MJ_READ                       0x03
    #define IRP_MJ_WRITE                      0x04
    #define IRP_MJ_QUERY_INFORMATION          0x05
    #define IRP_MJ_SET_INFORMATION            0x06
    #define IRP_MJ_QUERY_EA                   0x07
    #define IRP_MJ_SET_EA                     0x08
    #define IRP_MJ_FLUSH_BUFFERS              0x09
    #define IRP_MJ_QUERY_VOLUME_INFORMATION   0x0a
    #define IRP_MJ_SET_VOLUME_INFORMATION     0x0b
    #define IRP_MJ_DIRECTORY_CONTROL          0x0c
    #define IRP_MJ_FILE_SYSTEM_CONTROL        0x0d
    #define IRP_MJ_DEVICE_CONTROL             0x0e

So I get the value 455f5078 which is a pointer to IrpDeviceIoCtlHandler :

`kd> dd 0xffffe087d4d11b60+0x70+e*8 L2` 

    ffffe087`d4d11c40  455f5078 fffff802

I disassemble this memory space to ensure that I didn't make a miscalculation :

`kd> u 0xfffff802455f5078 L5`

    HEVD!IrpDeviceIoCtlHandler [c:\projects\hevd\driver\hevd\hacksysextremevulnerabledriver.c @ 259]:
    fffff802`455f5078 488bc4          mov     rax,rsp
    fffff802`455f507b 48895808        mov     qword ptr [rax+8],rbx
    fffff802`455f507f 48896810        mov     qword ptr [rax+10h],rbp
    fffff802`455f5083 48897018        mov     qword ptr [rax+18h],rsi
    fffff802`455f5087 48897820        mov     qword ptr [rax+20h],rdi

Now I can set a breakpoint on it.

`kd> bp 0xfffff802455f5078`

`kd> bl`

     0 d Enable Clear  u                      0001 (0001) (Displaying )
     1 e Disable Clear  fffff802`455f5078     0001 (0001) HEVD!IrpDeviceIoCtlHandler
     2 e Disable Clear  fffff802`47bca1e0     0001 (0001) nt!DbgBreakPointWithStatus

I tell to the debugee to continue execution and launch HackSysDriver exploit with -s (StackOverflow) -c cmd.exe options.

`kd> g`

The breakpoint is reached :-)

    Breakpoint 1 hit
    HEVD!IrpDeviceIoCtlHandler:
    fffff802`455f5078 488bc4          mov     rax,rsp

Here is a reminder of the IOCTL switch case.

`kd> u fffff802455f5078 L10`

    HEVD!IrpDeviceIoCtlHandler [c:\projects\hevd\driver\hevd\hacksysextremevulnerabledriver.c @ 259]:
    fffff802`455f5078 488bc4          mov     rax,rsp
    fffff802`455f507b 48895808        mov     qword ptr [rax+8],rbx
    fffff802`455f507f 48896810        mov     qword ptr [rax+10h],rbp
    fffff802`455f5083 48897018        mov     qword ptr [rax+18h],rsi
    fffff802`455f5087 48897820        mov     qword ptr [rax+20h],rdi
    fffff802`455f508b 4156            push    r14
    fffff802`455f508d 4883ec20        sub     rsp,20h
    fffff802`455f5091 4c8bb2b8000000  mov     r14,qword ptr [rdx+0B8h]
    fffff802`455f5098 488bea          mov     rbp,rdx
    fffff802`455f509b bebb0000c0      mov     esi,0C00000BBh
    fffff802`455f50a0 4d85f6          test    r14,r14
    fffff802`455f50a3 0f8472060000    je      HEVD!IrpDeviceIoCtlHandler+0x6a3 (fffff802`455f571b)
    fffff802`455f50a9 458b4e18        mov     r9d,dword ptr [r14+18h]
    fffff802`455f50ad b83b202200      mov     eax,22203Bh
    fffff802`455f50b2 443bc8          cmp     r9d,eax
    fffff802`455f50b5 0f8756030000    ja      HEVD!IrpDeviceIoCtlHandler+0x399 (fffff802`455f5411)

I continue execution until the comparison : is my IOCTL = 22203B ?

`kd> ta fffff802455f50b2`

    HEVD!IrpDeviceIoCtlHandler+0x3:
    fffff802`455f507b 48895808        mov     qword ptr [rax+8],rbx
    [...]
    fffff802`455f50b2 443bc8          cmp     r9d,eax

Yes it is, look at the registers :

`kd> r`

    rax=000000000022203b rbx=ffffe087d2d03490 rcx=ffffe087d4df1b70
    rdx=ffffe087d2d03490 rsi=00000000c00000bb rdi=ffffe087d70943b0
    rip=fffff802455f50b2 rsp=fffff081c404c7f0 rbp=ffffe087d2d03490
     r8=000000000000000e  r9=0000000000222003 r10=fffff802455f5078
    r11=0000000000000000 r12=0000000000000000 r13=0000000000000000
    r14=ffffe087d2d03560 r15=ffffe087d4df1b70
    iopl=0         nv up ei ng nz na po nc
    cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000286
    HEVD!IrpDeviceIoCtlHandler+0x3a:
    fffff802`455f50b2 443bc8          cmp     r9d,eax






## TODO
https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-user-mode-processes-without-symbols
Issue a k (Display Stack Backtrace) command on the symbol-less machine.
