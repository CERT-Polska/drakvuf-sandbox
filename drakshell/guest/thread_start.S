.intel_syntax noprefix
.globl thread_start
thread_start:

#if defined(__x86_64__)
    push rcx
#endif
#if defined(__i386__)
    push ecx
#endif
    call drakshell_main
    # This one is going to deallocate memory occupied by shellcode
    # and finish the thread to cover up all traces of drakshell
    # in explorer.exe
    #
    # We're going to jump to the VirtualFree and it is going to
    # return to the ExitThread for us.
#if defined(__x86_64__)
    pop rcx
    and rcx, -4096
    xor rdx, rdx
    mov r8, 0x8000
    jmp [rip+pVirtualFree]
#endif
#if defined(__i386__)
    # TODO: Deallocation for i386 not implemented
    pop ecx
    xor eax, eax
    ret
#endif
