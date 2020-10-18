CC=gcc
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -fPIE -D_FORTIFY_SOURCE=2
LDFLAGS=-lcrypto -lssl

ish2: ish2.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

noverify: ish2.c
	$(CC) $< -DNVERIFY $(CFLAGS) $(LDFLAGS) -o ish2

clean:
	rm -f ish2