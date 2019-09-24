#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "../src/hash/sha1.h"
#include "../src/mem/static.h"

uint8_t *given_dk[5] = {
	"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6",
	"\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57",
	"\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1",
	"\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84",
	"\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96"
	"\x4c\xf2\xf0\x70\x38"
};

#define UNUSED(x)	((void)(x))
#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

static void do_runtest_vector_1(void)
{
	int i;
	char *pwd = "password";
	char *salt = "salt";
	uint64_t iter_count = 1;
	size_t dklen = SHA1_OUTPUT_BLKSIZE;
	uint8_t buf[dklen];

	MSG_OUT("test vector #1\n");
	pbkdf2_hmac_sha1(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
	assert(!strcmp(buf, given_dk[0]));
	MSG_OUT("- password: %s\n", pwd);
	MSG_OUT("- salt: %s\n", salt);
	MSG_OUT("- iteration count: %lu\n", iter_count);
	MSG_OUT("- derived key length: %lu\n", dklen);
	MSG_OUT("- given derived key: ");
	for (i = 0; i < dklen; i++) {
		MSG_OUT("%02x ", given_dk[0][i]);
	}
	MSG_OUT("\n");
	MSG_OUT("- produced derived key: ");
	for (i = 0; i < dklen; i++) {
		MSG_OUT("%02x ", buf[i]);
	}
	MSG_OUT("\n\n");
	static_cleanup(buf, dklen * sizeof(uint8_t));
}

static void do_runtest_vector_2(void)
{
        int i;
        char *pwd = "password";
        char *salt = "salt";
        uint64_t iter_count = 2;
        size_t dklen = SHA1_OUTPUT_BLKSIZE;
        uint8_t buf[dklen];

        MSG_OUT("test vector #2\n");
        pbkdf2_hmac_sha1(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
        assert(!strcmp(buf, given_dk[1]));
        MSG_OUT("- password: %s\n", pwd);
        MSG_OUT("- salt: %s\n", salt);
        MSG_OUT("- iteration count: %lu\n", iter_count);
        MSG_OUT("- derived key length: %lu\n", dklen);
        MSG_OUT("- given derived key: ");
	for (i = 0; i < dklen; i++) {
                MSG_OUT("%02x ", given_dk[1][i]);
        }
        MSG_OUT("\n");
        MSG_OUT("- produced derived key: ");
        for (i = 0; i < dklen; i++) {
                MSG_OUT("%02x ", buf[i]);
        }
        MSG_OUT("\n\n");
        static_cleanup(buf, dklen * sizeof(uint8_t));
}

static void do_runtest_vector_3(void)
{
        int i;
        char *pwd = "password";
        char *salt = "salt";
        uint64_t iter_count = 4096;
        size_t dklen = SHA1_OUTPUT_BLKSIZE;
        uint8_t buf[dklen];

        MSG_OUT("test vector #3\n");
        pbkdf2_hmac_sha1(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
        assert(!strcmp(buf, given_dk[2]));
        MSG_OUT("- password: %s\n", pwd);
        MSG_OUT("- salt: %s\n", salt);
        MSG_OUT("- iteration count: %lu\n", iter_count);
        MSG_OUT("- derived key length: %lu\n", dklen);
        MSG_OUT("- given derived key: ");
	for (i = 0; i < dklen; i++) {
                MSG_OUT("%02x ", given_dk[2][i]);
        }
        MSG_OUT("\n");
        MSG_OUT("- produced derived key: ");
        for (i = 0; i < dklen; i++) {
                MSG_OUT("%02x ", buf[i]);
        }
        MSG_OUT("\n\n");
        static_cleanup(buf, dklen * sizeof(uint8_t));
}

static void do_runtest_vector_4(void)
{
        int i;
        char *pwd = "password";
        char *salt = "salt";
        uint64_t iter_count = 16777216;
        size_t dklen = SHA1_OUTPUT_BLKSIZE;
        uint8_t buf[dklen];

        MSG_OUT("test vector #4\n");
        pbkdf2_hmac_sha1(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
        assert(!strcmp(buf, given_dk[3]));
        MSG_OUT("- password: %s\n", pwd);
        MSG_OUT("- salt: %s\n", salt);
        MSG_OUT("- iteration count: %lu\n", iter_count);
        MSG_OUT("- derived key length: %lu\n", dklen);
        MSG_OUT("- given derived key: ");
        for (i = 0; i < dklen; i++) {
                MSG_OUT("%02x ", given_dk[3][i]);
        }
        MSG_OUT("\n");
        MSG_OUT("- produced derived key: ");
        for (i = 0; i < dklen; i++) {
                MSG_OUT("%02x ", buf[i]);
        }
        MSG_OUT("\n\n");
        static_cleanup(buf, dklen * sizeof(uint8_t));
}

static void do_runtest_vector_5(void)
{
        int i;
        char *pwd = "passwordPASSWORDpassword";
        char *salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
        uint64_t iter_count = 4096;
        size_t dklen = 25;
        uint8_t buf[dklen];

        MSG_OUT("test vector #5\n");
        pbkdf2_hmac_sha1(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
        assert(!strcmp(buf, given_dk[4]));
        MSG_OUT("- password: %s\n", pwd);
        MSG_OUT("- salt: %s\n", salt);
        MSG_OUT("- iteration count: %lu\n", iter_count);
        MSG_OUT("- derived key length: %lu\n", dklen);
        MSG_OUT("- given derived key: ");
        for (i = 0; i < dklen; i++) {
                MSG_OUT("%02x ", given_dk[4][i]);
        }
        MSG_OUT("\n");
        MSG_OUT("- produced derived key: ");
        for (i = 0; i < dklen; i++) {
                MSG_OUT("%02x ", buf[i]);
        }
        MSG_OUT("\n");
        static_cleanup(buf, dklen * sizeof(uint8_t));
}

int main(int argc, char **argv, char **envp)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(envp);

	MSG_OUT("-----[PBKDF2 HMAC SHA-1 Test Vector]-----\n");
	do_runtest_vector_1();
	do_runtest_vector_2();
	do_runtest_vector_3();
	do_runtest_vector_4();
	do_runtest_vector_5();
	MSG_OUT("-----------------------------------------\n");

	return 0;
}
