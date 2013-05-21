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

.globl thunk
thunk:
	movabs rax, 0
	mov rcx, rdi
	sub rsp, 40
	call rax
	add rsp, 40
	ret
