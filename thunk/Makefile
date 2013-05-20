all: a.o a64.o

disasm: a.o a64.o
	i386-elf-objdump -d -M intel a.o
	x86_64-elf-objdump -d -M intel a64.o

a.o: a.s
	i386-elf-gcc -c $<

a64.o: a64.s
	x86_64-elf-gcc -c $<

clean:
	rm -f *.o
