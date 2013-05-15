SUBDIRS = libc stest ctest multilib thunk

all:
	for dir in $(SUBDIRS); do $(MAKE) $@ -C $$dir || exit 1; done

clean:
	for dir in $(SUBDIRS); do $(MAKE) $@ -C $$dir || exit 1; done
