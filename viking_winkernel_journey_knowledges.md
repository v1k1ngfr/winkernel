# Table of Contents
1. [x64 software conventions](#x64_conventions)
2. [Windbg skill](#windbg_skill)

** ############### **

** Disclaimer **

** Why this memo ? It's just some notes / all information gathered during my "diving into the Windows kernel" journey. **

** I put all my copy / paste skill to create this note. Links are provided for more details (original author) about each chapter **

** ############### **

## x64 software conventions [](#){name=x64_conventions}
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

## Windbg skill [](#){name=windbg_skill}
[Link](https://web.archive.org/web/20170907000441/http://expdev-kiuhnm.rhcloud.com/2015/05/17/windbg/)

### Help
   * Help, use

`.hh <command>`

### Debug Strings
We enable printing Debug Strings via command:
`ed nt!Kd_Default_Mask 8`


### Symbols
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

`ed eip cc cc`

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

   * Disassembly
   * Memory
   * Command

Save the workspace (File→Save Workspace) after setting up the windows.

## Windows Drivers
[Link](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)

### Overview of the Windows I/O Model
The I/O manager presents a consistent interface to all kernel-mode drivers, including lowest-level, intermediate, and file system drivers. 

All I/O requests to drivers are sent as I/O request packets (IRPs).

### Summary
The I/O manager creates a driver object for each driver that has been installed and loaded. Driver objects are defined using DRIVER_OBJECT structures.

![Texte alternatif](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/images/3devobj.png)

When the I/O manager calls a driver's DriverEntry routine, it supplies the address of the driver's driver object. The driver object contains storage for entry points to many of a driver's standard routines. 
