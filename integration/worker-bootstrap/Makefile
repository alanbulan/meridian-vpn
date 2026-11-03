CC ?= cc
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=3
.PHONY: all test clean
all: build/meridian-worker-bootstrap
build/meridian-worker-bootstrap: bootstrap.c policy.h
	mkdir -p build
	$(CC) $(CFLAGS) -static -Wl,-z,relro,-z,now,-z,noexecstack -o $@ bootstrap.c
	readelf -l $@ > build/elf-program-headers.txt
	! grep -q INTERP build/elf-program-headers.txt
# This target never runs the production bootstrap, even if the caller is root.
test: build/test-bootstrap
	./build/test-bootstrap
build/test-bootstrap: test_bootstrap.c bootstrap.c policy.h
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ test_bootstrap.c
clean:
	rm -f build/meridian-worker-bootstrap build/test-bootstrap
