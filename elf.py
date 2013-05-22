#!/usr/bin/env python
from ctypes import *
from struct import unpack
from sys import stdout, argv, exit

c_getaddr = CFUNCTYPE(c_void_p, c_void_p)(lambda x: x)

def VirtualAlloc(address, size, allocationType, protect):
    pVirtualAlloc = windll.kernel32.VirtualAlloc
    VirtualAlloc = WINFUNCTYPE(
        POINTER(ARRAY(c_ubyte, size)),
        c_void_p, c_size_t, c_int, c_int)(
            c_getaddr(pVirtualAlloc))
    return VirtualAlloc(address, size, allocationType, protect)[0]

def VirtualFree(address, size, freeType):
    pVirtualFree = windll.kernel32.VirtualFree
    VirtualFree = WINFUNCTYPE(c_bool, c_void_p, c_int, c_int)(
        c_getaddr(pVirtualFree))
    return VirtualFree(address, size, freeType)

MEM_COMMIT  = 0x1000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40

jitbuf = VirtualAlloc(0, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
jitidx = 0

class JIT:
    def __init__(self, code):
        global jitidx
        self.offset = jitidx
        self.addr = c_getaddr(jitbuf) + jitidx
        jitidx += len(code)
        jitbuf[self.offset : jitidx] = code

def getaddr(p):
    return p.addr if isinstance(p, JIT) else c_getaddr(p)

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

aout = "a.out" if len(argv) != 2 else argv[1]
with open(aout, "rb") as f:
    elf = f.read()

def die(s):
    print s
    exit(1)

if len(elf) < 52:
    die("not found: ELF header")
if elf[0:4] != "\x7fELF":
    die("not fount: ELF signature")
if ord(elf[4]) != 1:
    die("not 32bit")
if ord(elf[5]) != 1:
    die("not little endian")

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

if e_type != 3:
    die("not PIE")
if e_machine != 3:
    die("not 386")

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
mem = VirtualAlloc(0, memlen, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
memoff = getaddr(mem)
memmin = memoff
memmax = memoff + memlen
print "[%08x]-[%08x] => [%08x]-[%08x]" % (
    0, memlen - 1, memoff, memmax - 1)

jmprel = None
pltgot = None

for ph in phs:
    if ph.p_type == 1: # PT_LOAD
        mem[ph.p_vaddr : ph.p_vaddr + ph.p_memsz] = map(
            ord, elf[ph.p_offset : ph.p_offset + ph.p_memsz])
        p = memoff + ph.p_vaddr
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

def getsymname(index):
    return readstr(strtab + read32(symtab + index * syment))

def readrel(addr):
    offset = read32(addr)
    info   = read32(addr + 4)
    print "[%08x]offset: %08x, info: %08x %s" % (
        addr, offset, info, getsymname(info >> 8))

def relocrel(addr):
    if memoff != 0:
        offset = memoff + read32(addr)
        write32(offset, memoff + read32(offset))

def linkrel(addr):
    offset = memoff + read32(addr)
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
    for addr in range(jmprel, jmprel + pltrelsz, 8):
        readrel(addr)
        if delayed:
            relocrel(addr)
        else:
            linkrel(addr)

def myinterp(id, offset):
    print "delayed link: id=%08x, offset=%08x" % (id, offset)
    return linkrel(jmprel + offset)

thunk_interp = CFUNCTYPE(c_void_p, c_void_p, c_uint64)(myinterp)
call_interp = JIT([
    0xff, 0x14, 0x24, # call [esp]
    0x83, 0xc4, 8,    # add esp, 8
    0x85, 0xc0,       # test eax, eax
    0x74, 2,          # jz 0f
    0xff, 0xe0,       # jmp eax
    0xc3 ])           # 0: ret
if pltgot != None:
    write32(pltgot + 4, getaddr(thunk_interp))
    write32(pltgot + 8, getaddr(call_interp))

print
CFUNCTYPE(None)(memoff + e_entry)()

VirtualFree(mem, 0, MEM_RELEASE)
VirtualFree(jitbuf, 0, MEM_RELEASE)
