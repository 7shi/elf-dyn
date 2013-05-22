.intel_syntax noprefix

.globl elfstart
elfstart:
	push rbp
	push rsi
	push rdi
	call rcx
	pop rdi
	pop rsi
	pop rbp
	ret

.globl interp
interp:
	pop rcx
	pop rdx
	sub rsp, 40
	call rcx
	add rsp, 40
	test rax, rax
	jz 0f
	jmp rax
0:	ret

.globl sysv2win64
sysv2win64:
	movabs rax, 0
	mov r9 , rcx
	mov r8 , rdx
	mov rdx, rsi
	mov rcx, rdi
	sub rsp, 40
	call rax
	add rsp, 40
	ret
