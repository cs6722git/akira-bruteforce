BITS 64

section .text

org 0x407F0E

mov rax, 2 ; file open
lea rdi, logfile
mov     rsi, 42h ; flags
mov     rdx, 1B6h ; mode
syscall 
push rax ; fd
mov     rdi, rax        
mov     rsi, [pointer]
mov     rdx, [counter]
shl     rdx, 3
mov     rax, 1 ; write
syscall
pop rdi ; fd
mov rax, 3; close
syscall
ret



logfile db "/tmp/log.bin", 0


section .data vstart=0x6B75B0
counter:

section .data2 vstart=0x6B75B8

pointer:
