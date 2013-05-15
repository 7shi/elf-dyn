TARGETS = a.out
LIBC    = ../libc/libc.so

all: $(TARGETS)

a.out: ctest.c $(LIBC)
	i386-elf-gcc -c $<
	i386-elf-ld -Ttext-segment 0x10000 -s -o $@ $(^:.c=.o)

$(LIBC):
	$(MAKE) -C `dirname $@`

clean:
	rm -f *.o $(TARGETS)
