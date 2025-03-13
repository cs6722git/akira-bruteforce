BITS 64

section .text

org 0x409650 
mov rdi, 0x1000000
call 0x05830F0 ; malloc
lea rsi, pointer
mov [rsi], rax


section .data vstart=0x6B75B0
counter:
section .data2 vstart=0x6B75B8

pointer:
