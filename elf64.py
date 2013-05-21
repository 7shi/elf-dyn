#!/usr/bin/env python64
from ctypes import *
from struct import unpack, pack
from sys import stdout, argv, exit

c_getaddr = CFUNCTYPE(c_void_p, c_void_p)(lambda x: x)

def VirtualAlloc(address, size, allocationType, protect):
    pVirtualAlloc = windll.kernel32.VirtualAlloc
    VirtualAlloc = CFUNCTYPE(
        POINTER(ARRAY(c_ubyte, size)),
        c_void_p, c_size_t, c_int, c_int)(
            c_getaddr(pVirtualAlloc))
    return VirtualAlloc(address, size, allocationType, protect)[0]

def VirtualFree(address, size, freeType):
    pVirtualFree = windll.kernel32.VirtualFree
    VirtualFree = CFUNCTYPE(c_bool, c_void_p, c_int, c_int)(
        c_getaddr(pVirtualFree))
    return VirtualFree(address, size, freeType)

MEM_COMMIT  = 0x1000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40

def write64(addr, val):
    cast(addr, POINTER(c_uint64))[0] = val

def read64(addr):
    return cast(addr, POINTER(c_uint64))[0]

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

jitbuf = VirtualAlloc(0, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
jitptr = 0

class JIT:
    def __init__(self, code):
        global jitptr
        self.offset = jitptr
        self.addr = c_getaddr(jitbuf) + jitptr
        jitptr += len(code)
        jitbuf[self.offset : jitptr] = code

class Thunk(JIT):
    def __init__(self, f):
        self.f = CFUNCTYPE(c_void_p, c_void_p)(f)
        addr = map(ord, pack("<Q", c_getaddr(self.f)))
        JIT.__init__(self, [
            0x48, 0xb8] + addr + [  # movabs rax, addr
            0x48, 0x89, 0xf9,       # mov rcx, rdi
            0x48, 0x83, 0xec, 0x28, # sub rsp, 40
            0xff, 0xd0,             # call rax
            0x48, 0x83, 0xc4, 0x28, # add rsp, 40
            0xc3 ])                 # ret

def getaddr(p):
    return p.addr if isinstance(p, JIT) else c_getaddr(p)

def putchar(ch):
    stdout.write(chr(ch))
    return ch

def puts(addr):
    s = readstr(addr)
    stdout.write(s)
    return len(s)

libc = {
    "putchar": Thunk(putchar),
    "puts"   : Thunk(puts) }

aout = "a64.out" if len(argv) != 2 else argv[1]
with open(aout, "rb") as f:
    elf = f.read()

def die(s):
    print s
    exit(1)

if len(elf) < 52:
    die("not found: ELF header")
if elf[0:4] != "\x7fELF":
    die("not fount: ELF signature")
if ord(elf[4]) != 2:
    die("not 64bit")
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
    "<HHLQQQLHHHHHH", elf[16:64])

if e_machine != 62:
    die("not x86-64")

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

p = e_phoff
phs = []

for i in range(e_phnum):
    phs += [Elf64_Phdr(elf, p)]
    p += e_phentsize

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
            type = read64(p)
            val  = read64(p + 8)
            if   type ==  0: break
            elif type ==  5: strtab   = val
            elif type ==  6: symtab   = val
            elif type == 11: syment   = val
            elif type == 23: jmprel   = val
            elif type ==  2: pltrelsz = val
            elif type ==  3: pltgot   = val
            p += 16

def getsymname(index):
    return readstr(strtab + read32(symtab + index * syment))

def readrel(addr):
    offset = read64(addr)
    info   = read64(addr + 8)
    addend = read64(addr + 16)
    print "[%08x]offset: %08x, info: %012x, addend: %08x %s" % (
        addr, offset, info, addend, getsymname(info >> 32))

def linkrel(addr):
    offset = read64(addr)
    name = getsymname(read64(addr + 8) >> 32)
    if libc.has_key(name):
        addr = getaddr(libc[name])
        print "linking: %s -> [%08x]%08x" % (name, offset, addr)
        write64(offset, addr)
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
        i += 24

def myinterp(id, offset):
    print "delayed link: id=%08x, offset=%08x" % (id, offset)
    return linkrel(jmprel + offset * 24)

thunk_interp = CFUNCTYPE(c_void_p, c_void_p, c_uint64)(myinterp)
call_interp = JIT([
    0x59,                   # pop rcx
    0x5a,                   # pop rdx
    0x48, 0x83, 0xec, 0x28, # sub rsp, 40
    0xff, 0xd1,             # call rcx
    0x48, 0x83, 0xc4, 0x28, # add rsp, 40
    0x48, 0x85, 0xc0,       # test rax, rax
    0x74, 0x02,             # jz 0f
    0xff, 0xe0,             # jmp rax
    0xc3 ])                 # ret
if pltgot != None:
    write64(pltgot +  8, getaddr(thunk_interp))
    write64(pltgot + 16, getaddr(call_interp))

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
CFUNCTYPE(None, c_void_p)(getaddr(elfstart))(e_entry)

VirtualFree(mem, 0, MEM_RELEASE)
VirtualFree(jitbuf, 0, MEM_RELEASE)
