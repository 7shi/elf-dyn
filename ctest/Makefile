TARGETS = a.out a64.out
LIBC    = ../libc/libc.so
LIBC64  = ../libc/libc64.so

all: $(TARGETS)

a.out: ctest.c $(LIBC)
	i386-elf-gcc -c $<
	i386-elf-ld -Ttext-segment 0x10000 -s -o $@ $(^:.c=.o)

a64.out: ctest.c $(LIBC64)
	x86_64-elf-gcc -c $<
	x86_64-elf-ld -Ttext-segment 0x200000 -s -o $@ $(^:.c=.o)

$(LIBC):
	$(MAKE) -C `dirname $@`

clean:
	rm -f *.o $(TARGETS)
