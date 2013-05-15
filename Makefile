TARGETS = a.out
SUBDIRS = ctest multilib thunk

all: $(TARGETS)
	for dir in $(SUBDIRS); do $(MAKE) $@ -C $$dir || exit 1; done

a.out: test.s elf.so
	i386-elf-gcc -c $<
	i386-elf-ld -Ttext-segment 0x10000 -s -o $@ $(^:.s=.o)

elf.so: putchar.c
	i386-elf-gcc -fPIC -c $<
	i386-elf-ld -shared -s -o $@ $(<:.c=.o)

clean:
	rm -f *.o *.so $(TARGETS)
	for dir in $(SUBDIRS); do $(MAKE) $@ -C $$dir || exit 1; done
