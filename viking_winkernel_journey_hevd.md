# Table of Contents
1. [Part 1 - setting up the lab](#lab_setup)
2. [Part 2 - getting familiar with HackSys Extreme Vulnerable Driver](#hevd_intro)

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

#### Writing a client application

#### Debugging without symbols
https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-user-mode-processes-without-symbols
Issue a k (Display Stack Backtrace) command on the symbol-less machine.















