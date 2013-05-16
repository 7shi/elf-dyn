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

class BinType:
    def __init__(self, size, getr, getf):
        self.size = size
        self.getr = getr
        self.getf = getf

    def read(self, data, pos):
        return unpack(self.getr, data[pos : pos + self.size])[0]

    def format(self, x):
        return self.getf % x

class BinEnum:
    def __init__(self, type, dict):
        self.type = type
        self.dict = dict
        self.size = type.size

    def read(self, data, pos):
        return self.type.read(data, pos)

    def format(self, x):
        ret = self.type.format(x)
        if self.dict.has_key(x):
            ret += " " + self.dict[x]
        return ret

class BinBuf:
    def __init__(self, size):
        self.size = size

    def read(self, data, pos):
        return data[pos : pos + self.size]

    def format(self, data):
        return str.join(" ", ["%02x" % ord(x) for x in data])

class BinStruct:
    def __init__(self, data, pos, format):
        self.pos = pos
        self.format = format
        self.maxlen = max([len(f[1]) for f in format])
        for f in format:
            self.__dict__[f[1]] = f[0].read(data, pos)
            pos += f[0].size
        self.length = pos - self.pos

    def dump(self):
        fmt = "%%-%ds:" % self.maxlen
        for f in self.format:
            print fmt % f[1], f[0].format(self.__dict__[f[1]])

Elf32_Addr  = BinType(4, "<L", "0x%08x")
Elf32_Half  = BinType(2, "<H", "0x%04x")
Elf32_Off   = BinType(4, "<L", "0x%08x")
Elf32_Sword = BinType(4, "<l", "%l")
Elf32_Word  = BinType(4, "<L", "0x%08x")

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

DT = {
     0: "DT_NULL",
     1: "DT_NEEDED",
     2: "DT_PLTRELSZ",
     3: "DT_PLTGOT",
     4: "DT_HASH",
     5: "DT_STRTAB",
     6: "DT_SYMTAB",
     7: "DT_RELA",
     8: "DT_RELASZ",
     9: "DT_RELAENT",
    10: "DT_STRSZ",
    11: "DT_SYMENT",
    12: "DT_INIT",
    13: "DT_FINI",
    14: "DT_SONAME",
    15: "DT_RPATH",
    16: "DT_SYMBOLIC",
    17: "DT_REL",
    18: "DT_RELSZ",
    19: "DT_RELENT",
    20: "DT_PLTREL",
    21: "DT_DEBUG",
    22: "DT_TEXTREL",
    23: "DT_JMPREL",
    0x70000000: "DT_LOPROC",
    0x7fffffff: "DT_HIPROC" }

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

interp = None
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
    elif pt == "PT_INTERP":
        interp = ph
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

if interp:
    stdout.write("interp: ")
    puts(interp.p_vaddr)
    print

dyns = {}

if dynamic:
    print "dynamic:"
    p = dynamic.p_vaddr
    dynlist = []
    while True:
        dyn = Elf32_Dyn(p)
        dynlist += [dyn]
        dyns[getenumstr(DT, dyn.d_tag, False)] = dyn.d_val
        p += dyn.size
        if dyn.d_tag == 0: break
    for dyn in dynlist:
        t1 = getenumstr(DT, dyn.d_tag, True)
        t2 = getenumstr(DT, dyn.d_tag, False)
        stdout.write("[%08x]%s: %08x " % (dyn.addr, t1, dyn.d_val))
        if t2 == "DT_NEEDED":
            puts(dyns["DT_STRTAB"] + dyn.d_val)
        print

def getsymname(index):
    p = dyns["DT_SYMTAB"] + index * dyns["DT_SYMENT"]
    return readstr(dyns["DT_STRTAB"] + read32(p))

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

if dyns.has_key("DT_JMPREL"):
    print
    print ".rel.plt(DT_JMPREL):"
    p = dyns["DT_JMPREL"]
    endp = p + dyns["DT_PLTRELSZ"]
    while p < endp:
        readrel(p)
        if not delayed: linkrel(p)
        p += 8

def myinterp(id, offset):
    print "delayed link: id=%08x, offset=%08x" % (id, offset)
    return linkrel(dyns["DT_JMPREL"] + offset)
thunk_interp = CFUNCTYPE(c_void_p, c_uint, c_uint)(myinterp)

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
write32(getaddr(call_interp) + 1, getaddr(thunk_interp))

if dyns.has_key("DT_PLTGOT"):
    p = dyns["DT_PLTGOT"]
    write32(p + 8, getaddr(call_interp))

print
CFUNCTYPE(None)(eh.e_entry)()

VirtualFree(call_interp, 0, MEM_RELEASE)
VirtualFree(mem, 0, MEM_RELEASE)
