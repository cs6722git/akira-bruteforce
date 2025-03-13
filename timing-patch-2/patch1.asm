BITS 64

section .text

org 0x49149F  
lea rsi, counter
mov rdi, [pointer]
mov rcx, [rsi]
inc qword [rsi]
mov     [rdi+rcx*8], rax
add rsp, 28h
ret


section .data vstart=0x6B75B0
counter:

section .data2 vstart=0x6B75B8

pointer:
