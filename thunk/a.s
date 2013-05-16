.intel_syntax noprefix
call [esp]
add esp, 8
test eax, eax
jz 0f
jmp eax
0: ret
