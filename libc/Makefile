TARGETS = libc.so libc64.so

all: $(TARGETS)

libc.so: libc.c
	i386-elf-gcc -fno-builtin -fPIC -c $<
	i386-elf-ld -shared -s -o $@ $(<:.c=.o)

libc64.so: libc.c
	x86_64-elf-gcc -fno-builtin -fPIC -c $<
	x86_64-elf-ld -shared -s -o $@ $(<:.c=.o)

clean:
	rm -f *.o $(TARGETS)
