#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "../src/hash/sha256.h"
#include "../src/mem/static.h"

uint8_t *given_dk[5] = {
	"\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22\x52\x56\xc4\xf8\x37\xa8\x65\x48\xc9\x2c\xcc\x35\x48\x08\x05\x98\x7c\xb7\x0b\xe1\x7b",
	"\xae\x4d\x0c\x95\xaf\x6b\x46\xd3\x2d\x0a\xdf\xf9\x28\xf0\x6d\xd0\x2a\x30\x3f\x8e\xf3\xc2\x51\xdf\xd6\xe2\xd8\x5a\x95\x47\x4c\x43",
	"\xc5\xe4\x78\xd5\x92\x88\xc8\x41\xaa\x53\x0d\xb6\x84\x5c\x4c\x8d\x96\x28\x93\xa0\x01\xce\x4e\x11\xa4\x96\x38\x73\xaa\x98\x13\x4a",
	"\xcf\x81\xc6\x6f\xe8\xcf\xc0\x4d\x1f\x31\xec\xb6\x5d\xab\x40\x89\xf7\xf1\x79\xe8\x9b\x3b\x0b\xcb\x17\xad\x10\xe3\xac\x6e\xba\x46",
	"\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11\x6e\x84\xcf\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1c\x4e\x2a\x1f\xb8\xdd\x53\xe1"
	"\xc6\x35\x51\x8c\x7d\xac\x47\xe9"
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
	size_t dklen = SHA256_OUTPUT_BLKSIZE;
	uint8_t buf[dklen];

	MSG_OUT("test vector #1\n");
	pbkdf2_hmac_sha256(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
	for (i = 0; i < dklen; i++) {
		assert(buf[i] == given_dk[0][i]);
        }
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
        size_t dklen = SHA256_OUTPUT_BLKSIZE;
        uint8_t buf[dklen];

        MSG_OUT("test vector #2\n");
        pbkdf2_hmac_sha256(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
        for (i = 0; i < dklen; i++) {
                assert(buf[i] == given_dk[1][i]);
        }
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
        size_t dklen = SHA256_OUTPUT_BLKSIZE;
        uint8_t buf[dklen];

        MSG_OUT("test vector #3\n");
        pbkdf2_hmac_sha256(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
        for (i = 0; i < dklen; i++) {
                assert(buf[i] == given_dk[2][i]);
        }
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
        size_t dklen = SHA256_OUTPUT_BLKSIZE;
        uint8_t buf[dklen];

        MSG_OUT("test vector #4\n");
        pbkdf2_hmac_sha256(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
        for (i = 0; i < dklen; i++) {
                assert(buf[i] == given_dk[3][i]);
        }
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
        size_t dklen = 40;
        uint8_t buf[dklen];

        MSG_OUT("test vector #5\n");
        pbkdf2_hmac_sha256(pwd, salt, strlen(pwd), strlen(salt), iter_count, dklen, buf);
        for (i = 0; i < dklen; i++) {
                assert(buf[i] == given_dk[4][i]);
        }
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

	MSG_OUT("-----[PBKDF2 HMAC SHA-256 Test Vector]-----\n");
	do_runtest_vector_1();
	do_runtest_vector_2();
	do_runtest_vector_3();
	do_runtest_vector_4();
	do_runtest_vector_5();
	MSG_OUT("-----------------------------------------\n");

	return 0;
}
