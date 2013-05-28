from ctypes import *

def c_getaddr(x):
    return cast(x, c_void_p).value

pVirtualAlloc = windll.kernel32.VirtualAlloc
pVirtualFree  = windll.kernel32.VirtualFree

c_VirtualAlloc = WINFUNCTYPE(
    c_void_p, c_void_p, c_size_t, c_int, c_int)(
    c_getaddr(pVirtualAlloc))
c_VirtualFree = WINFUNCTYPE(
    c_bool, c_void_p, c_int, c_int)(
    c_getaddr(pVirtualFree))

def VirtualAlloc(address, size, allocationType, protect):
    return cast(
        c_VirtualAlloc(address, size, allocationType, protect),
        POINTER(ARRAY(c_ubyte, size)))[0]

def VirtualFree(address, size, freeType):
    return c_VirtualFree(address, size, freeType)

MEM_COMMIT  = 0x1000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40

class JITAlloc:
    def __init__(self, size):
        self.mem = VirtualAlloc(
            0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        self.size = size
        self.addr = c_getaddr(self.mem)

    def __del__(self):
        VirtualFree(self.mem, 0, MEM_RELEASE)

class JIT(JITAlloc):
    def __init__(self, code):
        JITAlloc.__init__(self, len(code))
        self.mem[:] = code

def getaddr(p):
    return p.addr if isinstance(p, JITAlloc) else c_getaddr(p)

def write64(addr, val): cast(addr, POINTER(c_uint64))[0] = val
def write32(addr, val): cast(addr, POINTER(c_uint32))[0] = val
def write16(addr, val): cast(addr, POINTER(c_uint16))[0] = val
def write8 (addr, val): cast(addr, POINTER(c_uint8 ))[0] = val

def writeptr(addr, val):
    if sizeof(c_void_p) == 8:
        write64(addr, getaddr(val))
    else:
        write32(addr, getaddr(val))

def writebin(addr, data):
    memmove(addr, c_getaddr(data), len(data))

def read64(addr): return cast(addr, POINTER(c_uint64))[0]
def read32(addr): return cast(addr, POINTER(c_uint32))[0]
def read16(addr): return cast(addr, POINTER(c_uint16))[0]
def read8 (addr): return cast(addr, POINTER(c_uint8 ))[0]

def readstr(addr):
    p = cast(addr, POINTER(c_ubyte))
    i = 0
    s = ""
    while p[i]:
        s += chr(p[i])
        i += 1
    return s
