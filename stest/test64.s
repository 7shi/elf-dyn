.intel_syntax noprefix
.globl putchar
.globl _start
_start:
mov edi, 'A'
call putchar
ret
