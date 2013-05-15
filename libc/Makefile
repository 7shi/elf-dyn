TARGETS = libc.so

all: $(TARGETS)

libc.so: libc.c
	i386-elf-gcc -fno-builtin -fPIC -c $<
	i386-elf-ld -shared -s -o $@ $(<:.c=.o)

clean:
	rm -f *.o $(TARGETS)
