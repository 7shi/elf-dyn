TARGETS = a.out

all: $(TARGETS)

a.out: ctest.c ../libc/libc.so
	i386-elf-gcc -c $<
	i386-elf-ld -Ttext-segment 0x10000 -s -o $@ $(^:.c=.o)

clean:
	rm -f *.o $(TARGETS)
