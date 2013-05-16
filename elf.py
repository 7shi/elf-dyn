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

def read16(addr):
    return cast(addr, POINTER(c_uint16))[0]

def read8(addr):
    return cast(addr, POINTER(c_uint8))[0]

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

def getstr(data, pos):
    p = pos
    while ord(data[p]): p += 1
    return data[pos : p]

def getenumstr(dict, v, align):
    s = dict[v] if dict.has_key(v) else str(v)
    if not align: return s
    maxlen = max([len(x) for x in dict.values()])
    return ("%-" + str(maxlen) + "s") % s

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

class Elf32_Dyn:
    def __init__(self, addr):
        self.addr = addr
        self.d_tag = read32(addr)
        self.d_val = read32(addr + 4)
        self.size = 8

PT = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    0x70000000: "PT_LOPROC",
    0x7fffffff: "PT_HIPROC" }

with open("a.out", "rb") as f:
    elf = f.read()

eh = Elf32_Ehdr(elf, 0)

p = eh.e_phoff
phs = []
for i in range(eh.e_phnum):
    ph = Elf32_Phdr(elf, p)
    ph.pos = p
    phs += [ph]
    p += eh.e_phentsize

memmin = min([ph.p_vaddr for ph in phs])
memmax = max([ph.p_vaddr + ((ph.p_memsz + 3) & ~3) for ph in phs])
memlen = memmax - memmin
mem = VirtualAlloc(memmin, memlen, MEM_COMMIT, PAGE_EXECUTE_READWRITE)

dynamic = None
print
print "Program Headers"
for ph in phs:
    pt = getenumstr(PT, ph.p_type, False)
    if pt == "PT_LOAD":
        o = ph.p_vaddr - memmin
        mem[o : o + ph.p_memsz] = map(
            ord, elf[ph.p_offset : ph.p_offset + ph.p_memsz])
    elif pt == "PT_DYNAMIC":
        dynamic = ph
    pt2 = getenumstr(PT, ph.p_type, True)
    flags  = "R" if ph.p_flags & 4 == 4 else "-"
    flags += "W" if ph.p_flags & 2 == 2 else "-"
    flags += "X" if ph.p_flags & 1 == 1 else "-"
    print "[%08x]type: %s, offset: %08x, vaddr: %08x, flags: %s" % (
        ph.pos, pt2, ph.p_offset, ph.p_vaddr, flags)
    #ph.dump()

def dumpmem():
    print
    for i in range(0, memlen, 16):
        hlen = min(16, memlen - i)
        print "%08x:" % (memmin + i), str.join(
            " ", ["%02x" % mem[i + j] for j in range(hlen)])

print
print "[%08x]-[%08x]" % (memmin, memmax)

DT_NULL     = 0
DT_STRTAB   = 5
DT_SYMTAB   = 6
DT_SYMENT   = 11
DT_JMPREL   = 23
DT_PLTRELSZ = 2
DT_PLTGOT   = 3

jmprel = 0
pltgot = 0

if dynamic:
    print "dynamic:"
    p = dynamic.p_vaddr
    dynlist = []
    while True:
        type = read32(p)
        val  = read32(p + 4)
        if   type == DT_STRTAB  : strtab   = val
        elif type == DT_SYMTAB  : symtab   = val
        elif type == DT_SYMENT  : syment   = val
        elif type == DT_JMPREL  : jmprel   = val
        elif type == DT_PLTRELSZ: pltrelsz = val
        elif type == DT_PLTGOT  : pltgot   = val
        p += 8
        if type == 0: break

def getsymname(index):
    p = symtab + index * syment
    return readstr(strtab + read32(p))

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

if jmprel:
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
    0xb8, 0, 0, 0, 0, #    mov eax, 0
    0xff, 0xd0,       #    call eax
    0x83, 0xc4, 8,    #    add esp, 8
    0x85, 0xc0,       #    test eax, eax
    0x74, 2,          #    jz 0f
    0xff, 0xe0,       #    jmp eax
    0xc3 ]            # 0: ret
call_interp = VirtualAlloc(
    0, len(proto_interp), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
call_interp[:] = proto_interp
thunk_interp = CFUNCTYPE(c_void_p, c_uint, c_uint)(myinterp)
write32(getaddr(call_interp) + 1, getaddr(thunk_interp))
if pltgot: write32(pltgot + 8, getaddr(call_interp))

print
CFUNCTYPE(None)(eh.e_entry)()

VirtualFree(call_interp, 0, MEM_RELEASE)
VirtualFree(mem, 0, MEM_RELEASE)
