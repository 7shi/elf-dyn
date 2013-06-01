#!/usr/bin/env python
from ctypes import *
from struct import *
from sys import stdout, argv

aout = "a.out"
delay = False
for arg in argv[1:]:
    if arg == "-delay":
        delay = True
    else:
        aout = arg

VirtualAlloc = windll.kernel32.VirtualAlloc
VirtualAlloc.restype = c_void_p
VirtualAlloc.argtype = [c_void_p, c_size_t, c_int, c_int]

VirtualFree = windll.kernel32.VirtualFree
VirtualFree.restype = c_bool
VirtualFree.argtype = [c_void_p, c_int, c_int]

MEM_COMMIT  = 0x1000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40

def getaddr(x):
    return cast(x, c_void_p).value

def writebin(addr, data, offset, size):
    memmove(addr, getaddr(data) + offset, size)

def write32(addr, val):
    cast(addr, POINTER(c_uint32))[0] = val

def read32(addr):
    return cast(addr, POINTER(c_uint32))[0]

def read16(addr):
    return cast(addr, POINTER(c_uint16))[0]

def read8(addr):
    return cast(addr, POINTER(c_uint8))[0]

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

def Elf32_Ehdr(data, pos): return BinStruct(data, pos, [
    (BinBuf(16), "e_ident"),
    (Elf32_Half, "e_type"),
    (Elf32_Half, "e_machine"),
    (Elf32_Word, "e_version"),
    (Elf32_Addr, "e_entry"),
    (Elf32_Off , "e_phoff"),
    (Elf32_Off , "e_shoff"),
    (Elf32_Word, "e_flags"),
    (Elf32_Half, "e_ehsize"),
    (Elf32_Half, "e_phentsize"),
    (Elf32_Half, "e_phnum"),
    (Elf32_Half, "e_shentsize"),
    (Elf32_Half, "e_shnum"),
    (Elf32_Half, "e_shstrndx")])

def Elf32_Phdr(data, pos): return BinStruct(data, pos, [
    (BinEnum(Elf32_Word, PT), "p_type"),
    (Elf32_Off , "p_offset"),
    (Elf32_Addr, "p_vaddr"),
    (Elf32_Addr, "p_paddr"),
    (Elf32_Word, "p_filesz"),
    (Elf32_Word, "p_memsz"),
    (Elf32_Word, "p_flags"),
    (Elf32_Word, "p_align")])

def Elf32_Shdr(data, pos): return BinStruct(data, pos, [
    (Elf32_Word, "sh_name"),
    (Elf32_Word, "sh_type"),
    (Elf32_Word, "sh_flags"),
    (Elf32_Addr, "sh_addr"),
    (Elf32_Off , "sh_offset"),
    (Elf32_Word, "sh_size"),
    (Elf32_Word, "sh_link"),
    (Elf32_Word, "sh_info"),
    (Elf32_Word, "sh_addralign"),
    (Elf32_Word, "sh_entsize")])

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

with open(aout, "rb") as f:
    elf = f.read()

print "[%08x]Elf32_Ehdr" % 0
eh = Elf32_Ehdr(elf, 0)
eh.dump()

p = eh.e_phoff
phs = []
for i in range(eh.e_phnum):
    ph = Elf32_Phdr(elf, p)
    ph.num = i
    phs += [ph]
    p += ph.length

memlen = max([ph.p_vaddr + ph.p_memsz for ph in phs])
mem = VirtualAlloc(0, memlen, MEM_COMMIT, PAGE_EXECUTE_READWRITE)

interp = None
dynamic = None
print
print "Program Headers"
for ph in phs:
    pt = getenumstr(PT, ph.p_type, False)
    if pt == "PT_LOAD":
        writebin(mem + ph.p_vaddr, elf, ph.p_offset, ph.p_memsz)
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

p = eh.e_shoff
shs = []
for i in range(eh.e_shnum):
    sh = Elf32_Shdr(elf, p)
    sh.num = i
    shs += [sh]
    p += sh.length
if len(shs) > 0:
    shstr = shs[eh.e_shstrndx].sh_offset
    print
    print "Section Headers"
    for sh in shs:
        name = getstr(elf, shstr + sh.sh_name) if sh.sh_name > 0 else ""
        flags  = "X" if sh.sh_flags & 4 == 4 else "-"
        flags += "A" if sh.sh_flags & 2 == 2 else "-"
        flags += "W" if sh.sh_flags & 1 == 1 else "-"
        print "[%08x]offset: %08x, addr: %08x, flags: %s, name: %s" % (
            sh.pos, sh.sh_offset, sh.sh_addr, flags, name)
        #sh.dump()

print
print "[%08x]-[%08x]" % (mem, mem + memlen - 1)

if interp:
    stdout.write("interp: ")
    puts(mem + interp.p_vaddr)
    print

dyns = {}

if dynamic:
    print "dynamic:"
    p = mem + dynamic.p_vaddr
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
            puts(mem + dyns["DT_STRTAB"] + dyn.d_val)
        print

def getsymname(index):
    p = mem + dyns["DT_SYMTAB"] + index * dyns["DT_SYMENT"]
    return string_at(mem + dyns["DT_STRTAB"] + read32(p))

def link(addr):
    offset = mem + read32(addr)
    name = getsymname(read32(addr + 4) >> 8)
    if libc.has_key(name):
        addr = getaddr(libc[name])
        print "linking: %s -> [%08x]%08x" % (name, offset, addr)
        write32(offset, addr)
        return addr
    print "undefined reference:", name
    return 0

if dyns.has_key("DT_JMPREL"):
    print
    print ".rel.plt(DT_JMPREL):"
    p = mem + dyns["DT_JMPREL"]
    endp = p + dyns["DT_PLTRELSZ"]
    while p < endp:
        offset = read32(p)
        info   = read32(p + 4)
        print "[%08x]offset: %08x, info: %08x %s" % (
            p, offset, info, getsymname(info >> 8))
        if delay:
            addr = mem + offset
            write32(addr, mem + read32(addr))
        else:
            link(p)
        p += 8

def myinterp(id, offset):
    print "delayed link: id=%08x, offset=%08x" % (id, offset)
    return link(mem + dyns["DT_JMPREL"] + offset)

thunk_interp = CFUNCTYPE(c_void_p, c_uint, c_uint)(myinterp)
proto_interp = (
    "\xff\x14\x24"  # call [esp]
    "\x83\xc4\x08"  # add esp, 8
    "\x85\xc0"      # test eax, eax
    "\x74\x02"      # jz 0f
    "\xff\xe0"      # jmp eax
    "\xc3" )        # 0: ret
call_interp = VirtualAlloc(
    0, len(proto_interp), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
memmove(call_interp, getaddr(proto_interp), len(proto_interp))

if dyns.has_key("DT_PLTGOT"):
    p = mem + dyns["DT_PLTGOT"]
    write32(p + 4, getaddr(thunk_interp))
    write32(p + 8, call_interp)

print
if sizeof(c_void_p) == 4:
    CFUNCTYPE(None)(mem + eh.e_entry)()
else:
    print "can not execute 32bit code"

VirtualFree(call_interp, 0, MEM_RELEASE)
VirtualFree(mem, 0, MEM_RELEASE)
