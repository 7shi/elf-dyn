#!/usr/bin/env python
from ctypes import *
from struct import unpack
from sys import stdout, argv

# Win32API
VirtualAlloc = windll.kernel32.VirtualAlloc
VirtualFree  = windll.kernel32.VirtualFree
MEM_COMMIT   = 0x1000
MEM_RELEASE  = 0x8000
PAGE_EXECUTE_READWRITE = 0x40

# memory I/O
def write32(addr, val):
    cast(addr, POINTER(c_uint32))[0] = val
def read32(addr):
    return cast(addr, POINTER(c_uint32))[0]

# libc emulation
def putchar(ch):
    stdout.write(chr(ch))
    return ch
def puts(addr):
    s = string_at(addr)
    stdout.write(s)
    return len(s)
libc = {
    "putchar": CFUNCTYPE(c_int, c_int)(putchar),
    "puts"   : CFUNCTYPE(c_int, c_void_p)(puts) }

# read file
aout = "a.out" if len(argv) < 2 else argv[1]
with open(aout, "rb") as f:
    elf = f.read()

# ELF header
assert len(elf) >= 52,        "not found: ELF32 header"
assert elf[0:4] == "\x7fELF", "not found: ELF signature"
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

# program header
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
phs = [Elf32_Phdr(elf, e_phoff + i * e_phentsize)
       for i in range(e_phnum)]

# load
memlen = max([ph.p_vaddr + ph.p_memsz for ph in phs])
mem = VirtualAlloc(0, memlen, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
print "===== %08x-%08x => %08x-%08x" % (
    0, memlen - 1, mem, mem + memlen - 1)
jmprel = None
pelf = cast(elf, c_void_p).value
for ph in phs:
    addr = mem + ph.p_vaddr
    if ph.p_type == 1: # PT_LOAD
        o, sz = ph.p_offset, ph.p_memsz
        memmove(addr, pelf + o, sz)
        print "LOAD: %08x-%08x => %08x-%08x" % (
            o, o + sz - 1, addr, addr + sz - 1)
    elif ph.p_type == 2: # PT_DYNAMIC
        while True:
            type = read32(addr)
            val  = read32(addr + 4)
            if   type ==  0: break
            elif type ==  5: strtab   = mem + val
            elif type ==  6: symtab   = mem + val
            elif type == 11: syment   = val
            elif type == 23: jmprel   = mem + val
            elif type ==  2: pltrelsz = val
            addr += 8

# link
if jmprel != None:
    print
    print ".rel.plt(DT_JMPREL):"
    for reladdr in range(jmprel, jmprel + pltrelsz, 8):
        offset = read32(reladdr)
        info   = read32(reladdr + 4)
        stroff = read32(symtab + (info >> 8) * syment)
        name   = string_at(strtab + stroff)
        print "[%08x]offset: %08x, info: %08x; %s" % (
            reladdr, offset, info, name)
        assert libc.has_key(name), "undefined reference: " + name
        addr = mem + offset
        faddr = cast(libc[name], c_void_p).value
        print "linking: %s -> [%08x]%08x" % (name, addr, faddr)
        write32(addr, faddr)

# execute
print
CFUNCTYPE(None)(mem + e_entry)()

VirtualFree(mem, 0, MEM_RELEASE)
