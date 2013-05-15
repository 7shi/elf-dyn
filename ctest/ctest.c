void test(char start, const char *str) {
	int i;
	for (i = 0; i < 26; i++)
		putchar(start + i);
	putchar('\n');
	puts(str);
}

void _start() {
	test('A', "Hello, ELF!\n");
	test('a', "done.\n");
}
