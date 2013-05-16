#!/usr/bin/env python
from ctypes import *
from struct import *
from sys import stdout

def VirtualAlloc(address, size, allocationType, protect):
    VirtualAlloc = windll.kernel32.VirtualAlloc
    VirtualAlloc.restype = POINTER(ARRAY(c_ubyte, size))
    VirtualAlloc.argtype = [c_void_p, c_size_t, c_int, c_int]
    return VirtualAlloc(address, size, allocationType, protect)[0]

VirtualFree = windll.kernel32.VirtualFree
VirtualFree.argtype = [c_void_p, c_int, c_int]

MEM_COMMIT  = 0x1000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40

getaddr = CFUNCTYPE(c_void_p, c_void_p)(lambda x: x)

def write32(addr, val):
    cast(addr, POINTER(c_uint32))[0] = val

def read32(addr):
    return cast(addr, POINTER(c_uint32))[0]

def readstr(addr):
    p = cast(addr, POINTER(c_ubyte))
    i = 0
    s = ""
    while p[i]:
        s += chr(p[i])
        i += 1
    return s

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

class Elf32_Ehdr:
    def __init__(self, data, pos):
        self.ident = data[pos : pos + 16]
        (self.e_type,
         self.e_machine,
         self.e_version,
         self.e_entry,
         self.e_phoff,
         self.e_shoff,
         self.e_flags,
         self.e_ehsize,
         self.e_phentsize,
         self.e_phnum,
         self.e_shentsize,
         self.e_shnum,
         self.e_shstrndx) = unpack(
            "<HHLLLLLHHHHHH", data[pos + 16 : pos + 52])

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

with open("a.out", "rb") as f:
    elf = f.read()

eh = Elf32_Ehdr(elf, 0)

p = eh.e_phoff
phs = []

for i in range(eh.e_phnum):
    phs += [Elf32_Phdr(elf, p)]
    p += eh.e_phentsize

memmin = min([ph.p_vaddr for ph in phs])
memmax = max([ph.p_vaddr + ph.p_memsz for ph in phs])
memlen = memmax - memmin
mem = VirtualAlloc(memmin, memlen, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
print "[%08x]-[%08x]" % (memmin, memmax - 1)

jmprel = None
pltgot = None

for ph in phs:
    if ph.p_type == 1: # PT_LOAD
        o = ph.p_vaddr - memmin
        mem[o : o + ph.p_memsz] = map(
            ord, elf[ph.p_offset : ph.p_offset + ph.p_memsz])
        print "LOAD: %08x-%08x => %08x-%08x" % (
            ph.p_offset, ph.p_offset + ph.p_memsz - 1,
            ph.p_vaddr , ph.p_vaddr  + ph.p_memsz - 1)
    elif ph.p_type == 2: # PT_DYNAMIC
        p = ph.p_vaddr
        while True:
            type = read32(p)
            val  = read32(p + 4)
            if   type ==  0: break
            elif type ==  5: strtab   = val
            elif type ==  6: symtab   = val
            elif type == 11: syment   = val
            elif type == 23: jmprel   = val
            elif type ==  2: pltrelsz = val
            elif type ==  3: pltgot   = val
            p += 8

def getsymname(index):
    return readstr(strtab + read32(symtab + index * syment))

def readrel(addr):
    offset = read32(addr)
    info   = read32(addr + 4)
    print "[%08x]offset: %08x, info: %08x %s" % (
        addr, offset, info, getsymname(info >> 8))

def linkrel(addr):
    offset = read32(addr)
    name = getsymname(read32(addr + 4) >> 8)
    if libc.has_key(name):
        addr = getaddr(libc[name])
        print "linking: %s -> [%08x]%08x" % (name, offset, addr)
        write32(offset, addr)
        return addr
    print "undefined reference:", name
    return 0

delayed = True

if jmprel != None:
    print
    print ".rel.plt(DT_JMPREL):"
    i = 0
    while i < pltrelsz:
        readrel(jmprel + i)
        if not delayed: linkrel(jmprel + i)
        i += 8

def myinterp(id, offset):
    print "delayed link: id=%08x, offset=%08x" % (id, offset)
    return linkrel(jmprel + offset)

proto_interp = [
    0xff, 0x14, 0x24, #    call [esp]
    0x83, 0xc4, 8,    #    add esp, 8
    0x85, 0xc0,       #    test eax, eax
    0x74, 2,          #    jz 0f
    0xff, 0xe0,       #    jmp eax
    0xc3 ]            # 0: ret
call_interp = VirtualAlloc(
    0, len(proto_interp), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
call_interp[:] = proto_interp
thunk_interp = CFUNCTYPE(c_void_p, c_void_p, c_uint32)(myinterp)
if pltgot != None:
    write32(pltgot + 4, getaddr(thunk_interp))
    write32(pltgot + 8, getaddr(call_interp))

print
CFUNCTYPE(None)(eh.e_entry)()

VirtualFree(call_interp, 0, MEM_RELEASE)
VirtualFree(mem, 0, MEM_RELEASE)
