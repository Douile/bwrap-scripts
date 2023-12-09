# Setup PREFIX
ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

# Set program name
PROGRAM := mpv

# Build seccomp
LDFLAGS := -lseccomp
seccomp: seccomp.o
seccomp.bpf: seccomp
	./seccomp > seccomp.bpf

seccomp.bpf.b64: seccomp.bpf
	base64 -w 0 seccomp.bpf > seccomp.bpf.b64

# Insert seccomp into script template
bwrap-$(PROGRAM): seccomp.bpf.b64 bwrap-$(PROGRAM)-no-sc
	sed "s#^SECCOMP=\"\"#SECCOMP=\"$(file < seccomp.bpf.b64)\"#" bwrap-$(PROGRAM)-no-sc > bwrap-$(PROGRAM) || rm bwrap-$(PROGRAM)
	chmod 755 bwrap-$(PROGRAM)

all: bwrap-$(PROGRAM)

.PHONY: clean
clean:
	rm -f seccomp seccomp.o seccomp.bpf seccomp.bpf.b64 bwrap-$(PROGRAM)

.PHONY: install
install: bwrap-$(PROGRAM)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 bwrap-$(PROGRAM) $(DESTDIR)$(PREFIX)/bin/

.PHONY: list
list:
	@LC_ALL=C $(MAKE) -pRrq -f $(firstword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/(^|\n)# Files(\n|$$)/,/(^|\n)# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | grep -E -v -e '^[^[:alnum:]]' -e '^$@$$'

.DEFAULT_GOAL := all
