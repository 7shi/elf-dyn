all: a.o

disasm: a.o
	objdump -d -M intel $<
a.o: a.s
	gcc -c $<

clean:
	rm -f a.o
