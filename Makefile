CC ?= gcc

CFLAGS ?= -O3 -pipe
BASE_CFLAGS = -std=c11 -pedantic -D_GNU_SOURCE
CFLAGS += $(BASE_CFLAGS)

WFLAGS = -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wno-switch \
	 -Wmissing-declarations -Werror=implicit -Wdeclaration-after-statement \
	 -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wrestrict \
	 -Wnull-dereference -Wjump-misses-init -Wdouble-promotion -Wshadow \
	 -Wformat=2 -Wstrict-aliasing -Wno-unknown-warning-option \
	 -Wno-format-nonliteral -Wpedantic

all: seal sign

debug: CFLAGS := -g -Og -fsanitize=address -fsanitize=undefined $(BASE_CFLAGS)
debug: all

seal: seal.o lib.o
	$(CC) -o $@ $^ $(CFLAGS) -lsodium

sign: sign.o lib.o
	$(CC) -o $@ $^ $(CFLAGS) -lsodium

%.o: %.c
	$(CC) $< $(CFLAGS) $(WFLAGS) -c -o $@

%.s: %.c
	$(CC) $< $(CFLAGS) -fverbose-asm $(WFLAGS) -S -c -o $@

%.o: %.s
	$(CC) $< -c -o $@

clean:
	rm -f sign seal *.o *.s
