TARGETS = a.out a64.out

all: $(TARGETS)

a.out: test.c liba.so libb.so
	i386-elf-gcc -c $<
	i386-elf-ld -Ttext-segment 0x10000 -s -o $@ $(^:.c=.o)

liba.so: a.c
libb.so: b.c
liba.so libb.so:
	i386-elf-gcc -fPIC -c $<
	i386-elf-ld -shared -s -o $@ $(<:.c=.o)

a64.out: test.c liba64.so libb64.so
	x86_64-elf-gcc -c $<
	x86_64-elf-ld -Ttext-segment 0x10000 -z max-page-size=0x1000 -s -o $@ $(^:.c=.o)

liba64.so: a.c
libb64.so: b.c
liba64.so libb64.so:
	x86_64-elf-gcc -fPIC -c $<
	x86_64-elf-ld -shared -s -o $@ $(<:.c=.o)

clean:
	rm -f *.o *.so $(TARGETS)
