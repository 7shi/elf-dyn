.intel_syntax noprefix
pop rax
pop r10
push rcx
mov rcx, r10
sub rsp, 32
call rax
add rsp, 32
pop rcx
test rax, rax
jz 0f
jmp rax
0: ret
