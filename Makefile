CC = gcc
CFLAGS = -Wall -Wextra -O2

all: ecdh_assign_2 rsa_assign_2

ecdh_assign_2: ecdh_assign_2.c
	$(CC) $(CFLAGS) -o $@ $< -lsodium

rsa_assign_2: rsa_assign_2.c
	$(CC) $(CFLAGS) -o $@ $< -lgmp -lsodium

clean:
	rm -f ecdh_assign_2 rsa_assign_2