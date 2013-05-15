TARGETS = a.out

all: $(TARGETS)

a.out: test.c liba.so libb.so
	i386-elf-gcc -c $<
	i386-elf-ld -Ttext-segment 0x10000 -s -o $@ $(^:.c=.o)

liba.so: a.c
libb.so: b.c
liba.so libb.so:
	i386-elf-gcc -fPIC -c $<
	i386-elf-ld -shared -s -o $@ $(<:.c=.o)

clean:
	rm -f *.o *.so $(TARGETS)
