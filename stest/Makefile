TARGETS = a.out a64.out
LIBC    = ../libc/libc.so
LIBC64  = ../libc/libc64.so

all: $(TARGETS)

a.out: test.s $(LIBC)
	i386-elf-gcc -fPIE -c $<
	i386-elf-ld -pie -s -o $@ $(^:.s=.o)

a64.out: test64.s $(LIBC64)
	x86_64-elf-gcc -fPIE -c $<
	x86_64-elf-ld -pie -z max-page-size=0x1000 -s -o $@ $(^:.s=.o)

$(LIBC) $(LIBC64):
	$(MAKE) -C `dirname $@`

clean:
	rm -f *.o $(TARGETS)
