#!/usr/bin/env python
from jit import *
from struct import unpack
from sys import stdout, argv, exit

aout = "a.out"
delay = False
for arg in argv[1:]:
    if arg == "-delay":
        delay = True
    else:
        aout = arg

def putchar(ch):
    stdout.write(chr(ch))
    return ch

def puts(addr):
    s = readstr(addr)
    stdout.write(s)
    return len(s)

libc = {
    "putchar": CFUNCTYPE(c_int, c_int)(putchar),
    "puts"   : CFUNCTYPE(c_int, c_void_p)(puts) }

with open(aout, "rb") as f:
    elf = f.read()

assert len(elf) >= 52,        "not found: ELF32 header"
assert elf[0:4] == "\x7fELF", "not fount: ELF signature"
assert ord(elf[4]) == 1,      "not 32bit"
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
    "<HHLLLLLHHHHHH", elf[16:52])

assert e_type    == 3, "not PIE"
assert e_machine == 3, "not i386"

class Elf32_Phdr:
    def __init__(self, data, pos):
        (self.p_type,
         self.p_offset,
         self.p_vaddr,
         self.p_paddr,
         self.p_filesz,
         self.p_memsz,
         self.p_flags,
         self.p_align) = unpack(
            "<LLLLLLLL", data[pos : pos + 32])

p = e_phoff
phs = []

for i in range(e_phnum):
    phs += [Elf32_Phdr(elf, p)]
    p += e_phentsize

memlen = max([ph.p_vaddr + ph.p_memsz for ph in phs])
mem    = JITAlloc(memlen)
memoff = mem.addr
print "===== %08x-%08x => %08x-%08x" % (
    0, memlen - 1, memoff, memoff + memlen - 1)

jmprel = None
pltgot = None

for ph in phs:
    if ph.p_type == 1: # PT_LOAD
        p = memoff + ph.p_vaddr
        writebin(p, elf[ph.p_offset : ph.p_offset + ph.p_memsz])
        print "LOAD: %08x-%08x => %08x-%08x" % (
            ph.p_offset, ph.p_offset + ph.p_memsz - 1,
            p          , p           + ph.p_memsz - 1)
    elif ph.p_type == 2: # PT_DYNAMIC
        p = memoff + ph.p_vaddr
        while True:
            type = read32(p)
            val  = read32(p + 4)
            if   type ==  0: break
            elif type ==  5: strtab   = memoff + val
            elif type ==  6: symtab   = memoff + val
            elif type == 11: syment   = val
            elif type == 23: jmprel   = memoff + val
            elif type ==  2: pltrelsz = val
            elif type ==  3: pltgot   = memoff + val
            p += 8

def getsymname(info):
    return readstr(strtab + read32(symtab + (info >> 8) * syment))

def linkrel(reladdr):
    addr = memoff + read32(reladdr)
    name = getsymname(read32(reladdr + 4))
    if libc.has_key(name):
        faddr = getaddr(libc[name])
        print "linking: %s -> [%08x]%08x" % (name, addr, faddr)
        write32(addr, faddr)
        return faddr
    print "undefined reference:", name
    return 0

if jmprel != None:
    print
    print ".rel.plt(DT_JMPREL):"
    for reladdr in range(jmprel, jmprel + pltrelsz, 8):
        offset = read32(reladdr)
        info   = read32(reladdr + 4)
        print "[%08x]offset: %08x, info: %08x %s" % (
            reladdr, offset, info, getsymname(info))
        if delay:
            addr = memoff + offset
            write32(addr, memoff + read32(addr))
        else:
            linkrel(reladdr)

def interp(id, offset):
    print "delayed link: id=%08x, offset=%08x" % (id, offset)
    return linkrel(jmprel + offset)

thunk_interp = CFUNCTYPE(c_void_p, c_void_p, c_uint32)(interp)
call_interp = JIT([
    0xff, 0x14, 0x24, # call [esp]
    0x83, 0xc4, 8,    # add esp, 8
    0x85, 0xc0,       # test eax, eax
    0x74, 2,          # jz 0f
    0xff, 0xe0,       # jmp eax
    0xc3 ])           # 0: ret
if pltgot != None:
    writeptr(pltgot + 4, thunk_interp)
    writeptr(pltgot + 8, call_interp)

print
CFUNCTYPE(None)(memoff + e_entry)()
