.intel_syntax noprefix
.globl putchar
.globl _start
_start:
push 'A'
call putchar
add esp, 4
ret
