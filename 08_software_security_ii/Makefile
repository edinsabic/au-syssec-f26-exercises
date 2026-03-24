CC = gcc
CFLAGS = -fno-stack-protector -no-pie
PIE_CFLAGS = -fno-stack-protector -fPIE -pie

rop_me: rop_me.c lib.s
	$(CC) -o $@ $(CFLAGS) $^

rop_me_pie: rop_me.c lib.s
	$(CC) -o $@ $(PIE_CFLAGS) $^

rop_me_static: rop_me.c lib.s
	$(CC) -o $@ $^ -static
