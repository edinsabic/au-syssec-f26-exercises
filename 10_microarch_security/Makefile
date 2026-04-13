CC = gcc
CFLAGS = -g -O0 -w
# CFLAGS = -g -O3 -Wall -Wextra

.phony: all clean

all: cache-time flush-reload spectre out-of-order

%: %.c
	$(CC) -o $@ $(CFLAGS) $^

clean:
	rm -f address address_asan thread thread_tsan undefined undefined_ubsan
