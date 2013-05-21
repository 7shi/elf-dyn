.intel_syntax noprefix
.globl putchar
.globl _start
_start:
push rbp
mov rbp, rsp
mov edi, 'A'
call putchar
leave
ret
