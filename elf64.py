#!/usr/bin/env python64
from jit import *
from struct import unpack
from sys import stdout, argv

aout = "a64.out"
delay = False
for arg in argv[1:]:
    if arg == "-delay":
        delay = True
    else:
        aout = arg

def SYSV2WIN64(restype, *argtypes):
    assert len(argtypes) <= 4, "too long arguments"
    def init(f):
        ret = JIT([
            0x48, 0xb8] + [0]*8 + [ # movabs rax, addr
            0x49, 0x89, 0xc9,       # mov r9 , rcx
            0x49, 0x89, 0xd0,       # mov r8 , rdx
            0x48, 0x89, 0xf2,       # mov rdx, rsi
            0x48, 0x89, 0xf9,       # mov rcx, rdi
            0x48, 0x83, 0xec, 0x28, # sub rsp, 40
            0xff, 0xd0,             # call rax
            0x48, 0x83, 0xc4, 0x28, # add rsp, 40
            0xc3 ])                 # ret
        ret.f = CFUNCTYPE(restype, *argtypes)(f)
        writeptr(ret.addr + 2, ret.f)
        return ret
    return init

def putchar(ch):
    stdout.write(chr(ch))
    return ch

def puts(addr):
    s = readstr(addr)
    stdout.write(s)
    return len(s)

libc = {
    "putchar": SYSV2WIN64(c_int, c_int)(putchar),
    "puts"   : SYSV2WIN64(c_int, c_void_p)(puts) }

with open(aout, "rb") as f:
    elf = f.read()

assert len(elf) >= 64,        "not found: ELF64 header"
assert elf[0:4] == "\x7fELF", "not fount: ELF signature"
assert ord(elf[4]) == 2,      "not 64bit"
assert ord(elf[5]) == 1,      "not little endian"

(e_type,
 e_machine,
 e_version,
 e_entry,
 e_phoff,
 e_shoff,
 e_flags,
 e_ehsize,
 e_phentsize,
 e_phnum,
 e_shentsize,
 e_shnum,
 e_shstrndx) = unpack(
    "<HHLQQQLHHHHHH", elf[16:64])

assert e_type    ==  3, "not PIE"
assert e_machine == 62, "not x86-64"

class Elf64_Phdr:
    def __init__(self, data, pos):
        (self.p_type,
         self.p_flags,
         self.p_offset,
         self.p_vaddr,
         self.p_paddr,
         self.p_filesz,
         self.p_memsz,
         self.p_align) = unpack(
            "<LLQQQQQQ", data[pos : pos + 56])

phs = [Elf64_Phdr(elf, e_phoff + i * e_phentsize)
       for i in range(e_phnum)]

memlen = max([ph.p_vaddr + ph.p_memsz for ph in phs])
mem    = JITAlloc(memlen)
memoff = mem.addr
print "===== %08x-%08x => %08x-%08x" % (
    0, memlen - 1, memoff, memoff + memlen - 1)

jmprel = None
pltgot = None

for ph in phs:
    addr = memoff + ph.p_vaddr
    if ph.p_type == 1: # PT_LOAD
        writebin(addr, elf[ph.p_offset : ph.p_offset + ph.p_memsz])
        print "LOAD: %08x-%08x => %08x-%08x" % (
            ph.p_offset, ph.p_offset + ph.p_memsz - 1,
            addr       , addr        + ph.p_memsz - 1)
    elif ph.p_type == 2: # PT_DYNAMIC
        while True:
            type = read64(addr)
            val  = read64(addr + 8)
            if   type ==  0: break
            elif type ==  5: strtab   = memoff + val
            elif type ==  6: symtab   = memoff + val
            elif type == 11: syment   = val
            elif type == 23: jmprel   = memoff + val
            elif type ==  2: pltrelsz = val
            elif type ==  3: pltgot   = memoff + val
            addr += 16

def getsymname(info):
    return readstr(strtab + read32(symtab + (info >> 32) * syment))

def linkrel(reladdr):
    addr = memoff + read64(reladdr)
    name = getsymname(read64(reladdr + 8))
    if libc.has_key(name):
        faddr = getaddr(libc[name])
        print "linking: %s -> [%08x]%08x" % (name, addr, faddr)
        write64(addr, faddr)
        return faddr
    print "undefined reference:", name
    return 0

if jmprel != None:
    print
    print ".rel.plt(DT_JMPREL):"
    for reladdr in range(jmprel, jmprel + pltrelsz, 24):
        offset = read64(reladdr)
        info   = read64(reladdr + 8)
        addend = read64(reladdr + 16)
        print "[%08x]offset: %08x, info: %012x, addend: %08x %s" % (
            reladdr, offset, info, addend, getsymname(info))
        if delay:
            addr = memoff + offset
            write64(addr, memoff + read64(addr))
        else:
            linkrel(reladdr)

def interp(id, offset):
    print "delayed link: id=%08x, offset=%08x" % (id, offset)
    return linkrel(jmprel + offset * 24)

thunk_interp = CFUNCTYPE(c_void_p, c_void_p, c_uint64)(interp)
call_interp = JIT([
    0x59,                   # pop rcx
    0x5a,                   # pop rdx
    0x48, 0x83, 0xec, 0x28, # sub rsp, 40
    0xff, 0xd1,             # call rcx
    0x48, 0x83, 0xc4, 0x28, # add rsp, 40
    0x48, 0x85, 0xc0,       # test rax, rax
    0x74, 0x02,             # jz 0f
    0xff, 0xe0,             # jmp rax
    0xc3 ])                 # 0: ret
if pltgot != None:
    writeptr(pltgot +  8, thunk_interp)
    writeptr(pltgot + 16, call_interp)

elfstart = JIT([
    0x55,       # push rbp
    0x56,       # push rsi
    0x57,       # push rdi
    0xff, 0xd1, # call rcx
    0x5f,       # pop rdi
    0x5e,       # pop rsi
    0x5d,       # pop rbp
    0xc3 ])     # ret

print
CFUNCTYPE(None, c_void_p)(elfstart.addr)(memoff + e_entry)
