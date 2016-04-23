CC=gcc
LIBS=-lssl -lcrypto
CFLAGS=-std=gnu99
    
generate_rsa_pair: generate_rsa_pair.c
	$(CC) $(CFLAGS) $< $(LIBS) -o $@

.PHONY: clean

clean:
	rm -f generate_rsa_pair
