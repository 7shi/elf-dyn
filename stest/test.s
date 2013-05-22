.intel_syntax noprefix
.globl _start
_start:
	push ebx
	call 0f
0:	pop ebx
	add ebx, OFFSET FLAT:_GLOBAL_OFFSET_TABLE_+(.-0b)

	push 'A'
	call putchar@PLT
	add esp, 4

	pop ebx
	ret
