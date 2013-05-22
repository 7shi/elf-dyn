.intel_syntax noprefix
.globl _start
_start:
	push rbp

	mov edi, 'A'
	call putchar@PLT

	pop rbp
	ret
