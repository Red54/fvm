global vmx_run_helper

%define MSR_FS_BASE 				0c0000100h
%define MSR_GS_BASE 				0c0000101h

%define MSR_K6_STAR                 0c0000081h
%define MSR_K8_LSTAR                0c0000082h
%define MSR_K8_SF_MASK              0c0000084h
%define MSR_K8_KERNEL_GS_BASE       0c0000102h

%define HOST_RSP    				00006c14h
%define HOST_RIP    				00006c16h



%ifdef CONFIG_X86_64
%macro SAVE_SEG 2

%ifndef OS_LINUX
   mov     %2, es
   push    %1
   mov     %2, ds
   push    %1

   ; Special case for FS; Windows and Linux either don't use it or restore it when leaving kernel mode, Solaris OTOH doesn't and we must save it.
   mov     ecx, MSR_FS_BASE
   rdmsr
   push    rdx
   push    rax
   push    fs

   ; Special case for GS; OSes typically use swapgs to reset the hidden base register for GS on entry into the kernel. The same happens on exit
   mov     ecx, MSR_GS_BASE
   rdmsr
   push    rdx
   push    rax

   push    gs
%endif

%endmacro

; trashes, rax, rdx & rcx
%macro RESTORE_SEG 2
   ; Note: do not step through this code with a debugger!
%ifndef OS_LINUX

   xor     eax, eax
   mov     ds, ax
   mov     es, ax
   mov     fs, ax
   mov     gs, ax



   pop     gs

   pop     rax
   pop     rdx
   mov     ecx, MSR_GS_BASE
   wrmsr


   pop     fs

   pop     rax
   pop     rdx
   mov     ecx, MSR_FS_BASE
   wrmsr
   ; Now it's safe to step again


   pop     %1
   mov     ds, %2
   pop     %1
   mov     es, %2

%endif
%endmacro

%macro SAVE_REG 0
   push    r15
   push    r14
   push    r13
   push    r12
   push    r11
   push    r10
   push    r9
   push    r8
   push    rbx
   push    rsi
   push    rdi
%endmacro

%macro RESTORE_REG 0
   pop     rdi
   pop     rsi
   pop     rbx
   pop     r8
   pop     r9
   pop     r10
   pop     r11
   pop     r12
   pop     r13
   pop     r14
   pop     r15
%endmacro

; load host MSR
%macro LOAD_HOST_MSR 1
    mov     rcx, %1
    pop     rax
    pop     rdx
    wrmsr
%endmacro

; save guest MSR and load host`s

%macro __LOAD_HOST_MSR 2
    mov     rcx, %1
    rdmsr
    mov     dword [rsi + %2], eax
    mov     dword [rsi + %2 + 4], edx
    pop     rax
    pop     rdx
    wrmsr
%endmacro

%macro LOAD_GST_MSR 2
    mov     rcx, %1
    rdmsr
    push    rdx
    push    rax
    mov     edx, dword [rsi + %2 + 4]
    mov     eax, dword [rsi + %2]
    wrmsr
%endmacro





struc     cpu_reg
	.rax                resq    1
	.rcx                resq    1
	.rdx                resq    1
	.rbx                resq    1
	.rsp                resq    1
	.rbp                resq    1
	.rsi                resq    1
	.rdi                resq    1
	.r8                 resq    1
	.r9                 resq    1
	.r10                resq    1
	.r11                resq    1
	.r12                resq    1
	.r13                resq    1
	.r14                resq    1
	.r15                resq    1

	.rip                resq    1
	.rflags             resq    1

	.dr0                resq    1
	.dr1                resq    1
	.dr2                resq    1
	.dr3                resq    1
	.dr6                resq    1
	.dr7                resq    1
	.cr0                resq    1
	.cr2                resq    1
	.cr3                resq    1
	.cr4                resq    1

	.lstar              resq    1
	.star               resq    1
	.sfmask             resq    1
	.kernelgsbase       resq    1
endstruc

;unsigned long vmx_run_helper(unsigned long launched, struct cpu_reg* reg);

vmx_run_helper:
	; (in)  rcx: launched
	; (in)  rdx: reg
	; (out) rax
	push    rbp
    mov     rbp, rsp

    pushf
    cli

    ; save nonvolatile host registers
    SAVE_REG

    ; save host rip
    lea     r10, [.vmlaunch64_done wrt rip]
	;toooooooooo difficult to continue after vmlaunch? vmrun works perfectly.
    mov     rax, HOST_RIP
    vmwrite rax, r10

    ; save the params
    mov     rdi, rcx        ; launched
    mov     rsi, rdx        ; reg

    ; save segs
    SAVE_SEG rax, ax

    ; save LSTAR, CSTAR, SFMASK, KERNEL_GSBASE and restore the guest`s
    ; TODO: use vt`s automatic load feature
    ; LOAD_GST_MSR MSR_K8_LSTAR, 			cpu_reg.lstar
    ; LOAD_GST_MSR MSR_K6_STAR, 			cpu_reg.star
    ; LOAD_GST_MSR MSR_K8_SF_MASK, 			cpu_reg.sfmask
    ; LOAD_GST_MSR MSR_K8_KERNEL_GS_BASE, 	cpu_reg.kernelgsbase;

    push    rsi

    ; ldtr
    xor     eax, eax
    sldt    ax
    push    rax

    ; tr limit will be reset to 0x67
    str     eax
    push    rax

    ; vt resets limit to 0xffff
    sub     rsp, 16
    sgdt    [rsp]

    sub     rsp, 16
    sidt    [rsp]

    ; not safe!
    ; mov     rbx, [rsi + cpu_reg.dr6]
    ; mov     dr6, rbx

    ; cr2
    mov     rbx, qword [rsi + cpu_reg.cr2]
    mov     cr2, rbx

    mov     eax, HOST_RSP
    vmwrite rax, rsp
    ; rsp cant be changed after this point

    mov     rax, qword [rsi + cpu_reg.rax]
    mov     rbx, qword [rsi + cpu_reg.rbx]
    mov     rcx, qword [rsi + cpu_reg.rcx]
    mov     rdx, qword [rsi + cpu_reg.rdx]
    mov     rbp, qword [rsi + cpu_reg.rbp]
    mov     r8,  qword [rsi + cpu_reg.r8]
    mov     r9,  qword [rsi + cpu_reg.r9]
    mov     r10, qword [rsi + cpu_reg.r10]
    mov     r11, qword [rsi + cpu_reg.r11]
    mov     r12, qword [rsi + cpu_reg.r12]
    mov     r13, qword [rsi + cpu_reg.r13]
    mov     r14, qword [rsi + cpu_reg.r14]
    mov     r15, qword [rsi + cpu_reg.r15]

    ; rdi ? resume : launch
    cmp     rdi, 0
    je      .vmlauch64_lauch

    mov     rdi, qword [rsi + cpu_reg.rdi]
    mov     rsi, qword [rsi + cpu_reg.rsi]

    vmresume
	;fail
    jmp     .vmlaunch64_done

.vmlauch64_lauch:
    mov     rdi, qword [rsi + cpu_reg.rdi]
    mov     rsi, qword [rsi + cpu_reg.rsi]

    vmlaunch
	;fail
    jmp     .vmlaunch64_done;

.vmlaunch64_done:
    jc      near .vmxstart64_invalid_vmxon_ptr
    jz      near .vmxstart64_start_failed

    lidt    [rsp]
    add     rsp, 16
    lgdt    [rsp]
    add     rsp, 16

    push    rdi
	; skip ldtr & tr
    mov     rdi, [rsp + 8 * 3]

    mov     qword [rdi + cpu_reg.rax], rax
    mov     qword [rdi + cpu_reg.rbx], rbx
    mov     qword [rdi + cpu_reg.rcx], rcx
    mov     qword [rdi + cpu_reg.rdx], rdx
    mov     qword [rdi + cpu_reg.rsi], rsi
    mov     qword [rdi + cpu_reg.rbp], rbp
    mov     qword [rdi + cpu_reg.r8],  r8
    mov     qword [rdi + cpu_reg.r9],  r9
    mov     qword [rdi + cpu_reg.r10], r10
    mov     qword [rdi + cpu_reg.r11], r11
    mov     qword [rdi + cpu_reg.r12], r12
    mov     qword [rdi + cpu_reg.r13], r13
    mov     qword [rdi + cpu_reg.r14], r14
    mov     qword [rdi + cpu_reg.r15], r15

    pop     rax                                 ; the guest edi we pushed above
    mov     qword [rdi + cpu_reg.rdi], rax

    ; mov     rax, dr6
    ; mov     [rdi + cpu_reg.dr6], rax

	mov     rbx, cr2
	mov     [rdi + cpu_reg.cr2], rbx
	; tr
    pop     rbx
    sub     rsp, 16
    sgdt    [rsp]
    mov     rax, rbx
    and     al, 0F8h                                ; mask away TI and RPL bits, get descriptor offset.
    add     rax, [rsp + 2]                          ; eax <- GDTR.address + descriptor offset.
    and     dword [rax + 4], ~0200h                 ; clear busy flag (2nd type2 bit)
    ltr     bx
    add     rsp, 16

	; ldtr
    pop     rax
    lldt    ax

	; reg
    pop     rsi

    ; __LOAD_HOST_MSR MSR_K8_KERNEL_GS_BASE, 	cpu_reg.kernelgsbase
    ; __LOAD_HOST_MSR MSR_K8_SF_MASK, 			cpu_reg.sfmask
    ; __LOAD_HOST_MSR MSR_K6_STAR, 				cpu_reg.star
    ; __LOAD_HOST_MSR MSR_K8_LSTAR, 			cpu_reg.lstar

    RESTORE_SEG rax, ax

    RESTORE_REG

    mov     rax, 0

.vmstart64_end:
    popf
    pop     rbp
    ret


.vmxstart64_invalid_vmxon_ptr:
    ; Restore base and limit of the IDTR & GDTR
    lidt    [rsp]
    add     rsp, 16
    lgdt    [rsp]
    add     rsp, 16

	; tr
    pop     rbx
    sub     rsp, 16
    sgdt    [rsp]
    mov     rax, rbx
    and     al, 0F8h                                ; mask away TI and RPL bits, get descriptor offset.
    add     rax, [rsp + 2]                          ; eax <- GDTR.address + descriptor offset.
    and     dword [rax + 4], ~0200h                 ; clear busy flag (2nd type2 bit)
    ltr     bx
    add     rsp, 16

    ; ldtr
    pop     rax
    lldt    ax

	; reg
    pop     rsi


    ; __LOAD_HOST_MSR MSR_K8_KERNEL_GS_BASE, 	cpu_reg.kernelgsbase
    ; __LOAD_HOST_MSR MSR_K8_SF_MASK, 			cpu_reg.sfmask
    ; __LOAD_HOST_MSR MSR_K6_STAR, 				cpu_reg.star
    ; __LOAD_HOST_MSR MSR_K8_LSTAR, 			cpu_reg.lstar


    RESTORE_SEG rax, ax

    RESTORE_REG


    mov     rax, 1
    jmp     .vmstart64_end

.vmxstart64_start_failed:
    ; Restore base and limit of the IDTR & GDTR
    lidt    [rsp]
    add     rsp, 16
    lgdt    [rsp]
    add     rsp, 16

	; tr
    pop     rbx
    sub     rsp, 16
    sgdt    [rsp]
    mov     rax, rbx
    and     al, 0F8h                                ; mask away TI and RPL bits, get descriptor offset.
    add     rax, [rsp + 2]                          ; eax <- GDTR.address + descriptor offset.
    and     dword [rax + 4], ~0200h                 ; clear busy flag (2nd type2 bit)
    ltr     bx
    add     rsp, 16

    ; ldtr
    pop     rax
    lldt    ax

	; reg
    pop     rsi


    ; __LOAD_HOST_MSR MSR_K8_KERNEL_GS_BASE, 	cpu_reg.kernelgsbase
    ; __LOAD_HOST_MSR MSR_K8_SF_MASK, 			cpu_reg.sfmask
    ; __LOAD_HOST_MSR MSR_K6_STAR, 				cpu_reg.star
    ; __LOAD_HOST_MSR MSR_K8_LSTAR, 			cpu_reg.lstar


    RESTORE_SEG rax, ax

    RESTORE_REG


    mov     rax, 1
    jmp     .vmstart64_end

%endif ;CONFIG_X86_64

%ifdef CONFIG_X86_32
;unsigned long vmx_run_helper(unsigned long launched, struct cpu_reg* reg);

vmx_run_helper:
	; (in)  ecx: launched
	; (in)  edx: reg
	; (out) eax
	mov eax, 1
	ret

%endif ;CONFIG_X86_32
