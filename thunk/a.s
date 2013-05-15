.intel_syntax noprefix
mov eax, 0x12345678
call eax
add esp, 8
test eax, eax
jz 0f
jmp eax
0: ret
