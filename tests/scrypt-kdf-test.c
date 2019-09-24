/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../src/scrypt.h"
#include "../src/mem/static.h"

#define UNUSED(x)	((void)(x))
#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

uint8_t *test_vector[4] = {
	// vector #1
	"\x77\xd6\x57\x62\x38\x65\x7b\x20\x3b\x19\xca\x42\xc1\x8a\x04\x97"
	"\xf1\x6b\x48\x44\xe3\x07\x4a\xe8\xdf\xdf\xfa\x3f\xed\xe2\x14\x42"
	"\xfc\xd0\x06\x9d\xed\x09\x48\xf8\x32\x6a\x75\x3a\x0f\xc8\x1f\x17"
	"\xe8\xd3\xe0\xfb\x2e\x0d\x36\x28\xcf\x35\xe2\x0c\x38\xd1\x89\x06",

	// vector #2
	"\xfd\xba\xbe\x1c\x9d\x34\x72\x00\x78\x56\xe7\x19\x0d\x01\xe9\xfe"
	"\x7c\x6a\xd7\xcb\xc8\x23\x78\x30\xe7\x73\x76\x63\x4b\x37\x31\x62"
	"\x2e\xaf\x30\xd9\x2e\x22\xa3\x88\x6f\xf1\x09\x27\x9d\x98\x30\xda"
	"\xc7\x27\xaf\xb9\x4a\x83\xee\x6d\x83\x60\xcb\xdf\xa2\xcc\x06\x40",

	// vector #3
	"\x70\x23\xbd\xcb\x3a\xfd\x73\x48\x46\x1c\x06\xcd\x81\xfd\x38\xeb"
	"\xfd\xa8\xfb\xba\x90\x4f\x8e\x3e\xa9\xb5\x43\xf6\x54\x5d\xa1\xf2"
	"\xd5\x43\x29\x55\x61\x3f\x0f\xcf\x62\xd4\x97\x05\x24\x2a\x9a\xf9"
	"\xe6\x1e\x85\xdc\x0d\x65\x1e\x40\xdf\xcf\x01\x7b\x45\x57\x58\x87",

	// vector #4
	"\x21\x01\xcb\x9b\x6a\x51\x1a\xae\xad\xdb\xbe\x09\xcf\x70\xf8\x81"
	"\xec\x56\x8d\x57\x4a\x2f\xfd\x4d\xab\xe5\xee\x98\x20\xad\xaa\x47"
	"\x8e\x56\xfd\x8f\x4b\xa5\xd0\x9f\xfa\x1c\x6d\x92\x7c\x40\xf4\xc3"
	"\x37\x30\x40\x49\xe8\xa9\x52\xfb\xcb\xf4\x5c\x6f\xa7\x7a\x41\xa4"
};

static void do_test_vector1(void)
{
	uint8_t buf[64];
	uint8_t *password = "";
	uint8_t *salt = "";
	uint64_t N = 16;
	uint32_t r = 1, p = 1;
	size_t dklen = 64, i;

	crypto_scrypt_kdf(password, salt, 0, 0, N, r, p, buf, dklen);

	for (i = 0; i < dklen; i++) {
		assert(buf[i] == test_vector[0][i]);
	}

	MSG_OUT("[Test Vector #1]\n");
	MSG_OUT("- password: \"\"\n");
	MSG_OUT("- salt: \"\"\n");
	MSG_OUT("- N (CPU/Memory Cost): %lu\n", N);
	MSG_OUT("- r (Block Size): %u\n", r);
	MSG_OUT("- p (Parallelization): %u\n", p);
	MSG_OUT("- dklen (Derived Key Length): %ld\n", dklen);
	MSG_OUT("- Given DK:\n");

	for (i = 0; i < dklen; i += 8) {
		MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x\n",
			test_vector[0][i + 0], test_vector[0][i + 1], test_vector[0][i + 2], test_vector[0][i + 3],
			test_vector[0][i + 4], test_vector[0][i + 5], test_vector[0][i + 6], test_vector[0][i + 7]);
	}

	MSG_OUT("- Generated DK:\n");

	for (i = 0; i < dklen; i += 8) {
                MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x\n",
                        buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3],
                        buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]);
        }

	MSG_OUT("\n");

	static_cleanup(buf, 64 * sizeof(uint8_t));
}

static void do_test_vector2(void)
{
	uint8_t buf[64];
	const uint8_t *password = "password";
	const uint8_t *salt = "NaCl";
	uint64_t N = 1024;
	uint32_t r = 8, p = 16;
	size_t dklen = 64, i;
	int q;

	q = crypto_scrypt_kdf((const uint8_t *)password, (const uint8_t *)salt, strlen(password), strlen(salt), N, r, p, buf, dklen);

	for (i = 0; i < dklen; i++) {
		assert(buf[i] == test_vector[1][i]);
	}

	MSG_OUT("[Test Vector #2]\n");
	MSG_OUT("- password: \"%s\"\n", password);
	MSG_OUT("- salt: \"%s\"\n", salt);
	MSG_OUT("- N (CPU/Memory Cost): %lu\n", N);
	MSG_OUT("- r (Block Size): %u\n", r);
	MSG_OUT("- p (Parallelization): %u\n", p);
	MSG_OUT("- dklen (Derived Key Length): %ld\n", dklen);
	MSG_OUT("- Given DK:\n");

	for (i = 0; i < dklen; i += 8) {
		MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x\n",
			test_vector[1][i + 0], test_vector[1][i + 1], test_vector[1][i + 2], test_vector[1][i + 3],
			test_vector[1][i + 4], test_vector[1][i + 5], test_vector[1][i + 6], test_vector[1][i + 7]);
	}

	MSG_OUT("- Generated DK:\n");

	for (i = 0; i < dklen; i += 8) {
                MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x\n",
                        buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3],
                        buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]);
        }

	MSG_OUT("\n");

	static_cleanup(buf, 64 * sizeof(uint8_t));
}

static void do_test_vector3(void)
{
	uint8_t buf[64];
	const uint8_t *password = "pleaseletmein";
	const uint8_t *salt = "SodiumChloride";
	uint64_t N = 16384;
	uint32_t r = 8, p = 1;
	size_t dklen = 64, i;
	int q;

	q = crypto_scrypt_kdf((const uint8_t *)password, (const uint8_t *)salt, strlen(password), strlen(salt), N, r, p, buf, dklen);

	for (i = 0; i < dklen; i++) {
		assert(buf[i] == test_vector[2][i]);
	}

	MSG_OUT("[Test Vector #3]\n");
	MSG_OUT("- password: \"%s\"\n", password);
	MSG_OUT("- salt: \"%s\"\n", salt);
	MSG_OUT("- N (CPU/Memory Cost): %lu\n", N);
	MSG_OUT("- r (Block Size): %u\n", r);
	MSG_OUT("- p (Parallelization): %u\n", p);
	MSG_OUT("- dklen (Derived Key Length): %ld\n", dklen);
	MSG_OUT("- Given DK:\n");

	for (i = 0; i < dklen; i += 8) {
		MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x\n",
			test_vector[2][i + 0], test_vector[2][i + 1], test_vector[2][i + 2], test_vector[2][i + 3],
			test_vector[2][i + 4], test_vector[2][i + 5], test_vector[2][i + 6], test_vector[2][i + 7]);
	}

	MSG_OUT("- Generated DK:\n");

	for (i = 0; i < dklen; i += 8) {
                MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x\n",
                        buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3],
                        buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]);
        }

	MSG_OUT("\n");

	static_cleanup(buf, 64 * sizeof(uint8_t));
}

static void do_test_vector4(void)
{
	uint8_t buf[64];
	const uint8_t *password = "pleaseletmein";
	const uint8_t *salt = "SodiumChloride";
	uint64_t N = 1048576;
	uint32_t r = 8, p = 1;
	size_t dklen = 64, i;
	int q;

	q = crypto_scrypt_kdf((const uint8_t *)password, (const uint8_t *)salt, strlen(password), strlen(salt), N, r, p, buf, dklen);

	for (i = 0; i < dklen; i++) {
		assert(buf[i] == test_vector[3][i]);
	}

	MSG_OUT("[Test Vector #4]\n");
	MSG_OUT("- password: \"%s\"\n", password);
	MSG_OUT("- salt: \"%s\"\n", salt);
	MSG_OUT("- N (CPU/Memory Cost): %lu\n", N);
	MSG_OUT("- r (Block Size): %u\n", r);
	MSG_OUT("- p (Parallelization): %u\n", p);
	MSG_OUT("- dklen (Derived Key Length): %ld\n", dklen);
	MSG_OUT("- Given DK:\n");

	for (i = 0; i < dklen; i += 8) {
		MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x\n",
			test_vector[3][i + 0], test_vector[3][i + 1], test_vector[3][i + 2], test_vector[3][i + 3],
			test_vector[3][i + 4], test_vector[3][i + 5], test_vector[3][i + 6], test_vector[3][i + 7]);
	}

	MSG_OUT("- Generated DK:\n");

	for (i = 0; i < dklen; i += 8) {
                MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x\n",
                        buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3],
                        buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]);
        }

	MSG_OUT("\n");

	static_cleanup(buf, 64 * sizeof(uint8_t));
}

int main(int argc, char **argv, char **envp)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(envp);

	MSG_OUT("-----[SCRYPT key derivation function test vector]-----\n");
	do_test_vector1();
	do_test_vector2();
	do_test_vector3();
	do_test_vector4();
	MSG_OUT("------------------------------------------------------\n");

	return 0;
}
