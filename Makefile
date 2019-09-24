CC = gcc
DEBUG = -g -ggdb
CFLAGS = -O2 -std=c99 -fPIC -W -Wall -Werror $(DEBUG)

LIB_OBJS = \
	./src/hash/sha1.o \
	./src/hash/sha1-hmac.o \
	./src/hash/sha1-pbkdf2.o \
	./src/hash/sha256.o \
	./src/hash/sha256-hmac.o \
	./src/hash/sha256-pbkdf2.o \
	./src/mem/static.o \
	./src/salsa_20_8.o \
	./src/scrypt-block-mix.o \
	./src/scrypt-romix.o \
	./src/scrypt-kdf.o

SHARED_LIB = ./libscrypt.so

$(SHARED_LIB): $(LIB_OBJS)
	$(CC) -shared -Wl,--export-dynamic $(LIB_OBJS) -o $(SHARED_LIB)

sha1-fips-test:
	$(CC) -o ./tests/sha1-fips-test ./tests/sha1-fips-test.c $(shell pwd)/$(SHARED_LIB)

hmac-sha1-test:
	$(CC) -o ./tests/hmac-sha1-test ./tests/hmac-sha1-test.c $(shell pwd)/$(SHARED_LIB)

pbkdf2-sha1-test:
	$(CC) -o ./tests/pbkdf2-sha1-test ./tests/pbkdf2-sha1-test.c $(shell pwd)/$(SHARED_LIB)

sha256-fips-test:
	$(CC) -o ./tests/sha256-fips-test ./tests/sha256-fips-test.c $(shell pwd)/$(SHARED_LIB)

hmac-sha256-test:
	$(CC) -o ./tests/hmac-sha256-test ./tests/hmac-sha256-test.c $(shell pwd)/$(SHARED_LIB)

pbkdf2-sha256-test:
	$(CC) -o ./tests/pbkdf2-sha256-test ./tests/pbkdf2-sha256-test.c $(shell pwd)/$(SHARED_LIB)

salsa-20-8-core-test:
	$(CC) -o ./tests/salsa-20-8-core-test ./tests/salsa-20-8-core-test.c $(shell pwd)/$(SHARED_LIB)

block-mix-test:
	$(CC) -o ./tests/block-mix-test ./tests/block-mix-test.c $(shell pwd)/$(SHARED_LIB)

rom-mix-test:
	$(CC) -o ./tests/rom-mix-test ./tests/rom-mix-test.c $(shell pwd)/$(SHARED_LIB)

scrypt-kdf-test:
	$(CC) -o ./tests/scrypt-kdf-test ./tests/scrypt-kdf-test.c $(shell pwd)/$(SHARED_LIB)

clean:
	rm -f ./src/*.o ./src/hash/*.o ./src/mem/*.o ./src/bits/*.o ./libscrypt.so ./tests/hmac-sha1-test ./tests/pbkdf2-sha1-test \
	./tests/sha1-fips-test ./tests/sha256-fips-test ./tests/hmac-sha256-test ./tests/pbkdf2-sha256-test ./tests/salsa-20-8-core-test \
	./tests/block-mix-test ./tests/rom-mix-test ./tests/scrypt-kdf-test
