#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../src/hash/sha256.h"
#include "../src/mem/static.h"

#define UNUSED(x)	((void)(x))
#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

uint8_t *given_hash[4] = {
	"b0344c61 d8db3853 5ca8afce af0bf12b 881dc200 c9833da7 26e9376c 2e32cff7",
	"5bdcc146 bf60754e 6a042426 089575c7 5a003f08 9d273983 9dec58b9 64ec3843",
	"773ea91e 36800e46 854db8eb d09181a7 2959098b 3ef8c122 d9635514 ced565fe",
	"82558a38 9a443c0e a4cc8198 99f2083a 85f0faa3 e578f807 7a2e3ff4 6729665b"
};

char *key_vec[4] = {
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",

	"Jefe",

	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",

	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
	"\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
	"\x15\x16\x17\x18\x19"
};

char *data_vec[4] = {
	"Hi There",

	"what do ya want for nothing?",

	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",

	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
};

int main(int argc, char **argv, char **envp)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(envp);

	char buf[71];
	uint32_t hash[SHA256_OUTPUT_WORDSIZE];
	hmac_sha256_ctx_t ctx;

	MSG_OUT("-----[HMAC SHA-256 Test Vector]-----\n");
	MSG_OUT("test vector #1\n");
	hmac_sha256_init(&ctx, key_vec[0], strlen(key_vec[0]));
	hmac_sha256_update(&ctx, data_vec[0], strlen(data_vec[0]));
	hmac_sha256_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3],
		hash[4], hash[5], hash[6], hash[7]);
	assert(!strcmp(buf, given_hash[0]));
	MSG_OUT("- key: 0x0b (20 times)\n");
	MSG_OUT("- data: %s\n", data_vec[0]);
	MSG_OUT("- given hash: %s\n", given_hash[0]);
	MSG_OUT("- produced hash: %s\n\n", buf);
	static_cleanup(buf, 71 * sizeof(char));
	static_cleanup(hash, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));

	MSG_OUT("test vector #2\n");
	hmac_sha256_init(&ctx, key_vec[1], strlen(key_vec[1]));
	hmac_sha256_update(&ctx, data_vec[1], strlen(data_vec[1]));
	hmac_sha256_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3],
		hash[4], hash[5], hash[6], hash[7]);
	assert(!strcmp(buf, given_hash[1]));
	MSG_OUT("- key: %s\n", key_vec[1]);
	MSG_OUT("- data: %s\n", data_vec[1]);
	MSG_OUT("- given hash: %s\n", given_hash[1]);
	MSG_OUT("- produced hash: %s\n\n", buf);
	static_cleanup(buf, 71 * sizeof(char));
	static_cleanup(hash, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));

	MSG_OUT("test vector #3\n");
	hmac_sha256_init(&ctx, key_vec[2], strlen(key_vec[2]));
	hmac_sha256_update(&ctx, data_vec[2], strlen(data_vec[2]));
	hmac_sha256_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3],
		hash[4], hash[5], hash[6], hash[7]);
	assert(!strcmp(buf, given_hash[2]));
	MSG_OUT("- key: 0xaa (20 times)\n");
	MSG_OUT("- data: 0xdd (50 times)\n");
	MSG_OUT("- given hash: %s\n", given_hash[2]);
	MSG_OUT("- produced hash: %s\n\n", buf);
	static_cleanup(buf, 71 * sizeof(char));
	static_cleanup(hash, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));

	MSG_OUT("test vector #4\n");
	hmac_sha256_init(&ctx, key_vec[3], strlen(key_vec[3]));
	hmac_sha256_update(&ctx, data_vec[3], strlen(data_vec[3]));
	hmac_sha256_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3],
		hash[4], hash[5], hash[6], hash[7]);
	assert(!strcmp(buf, given_hash[3]));
	MSG_OUT("- key: 0x01..0x19\n");
	MSG_OUT("- data: 0xcd (50 times)\n");
	MSG_OUT("- given hash: %s\n", given_hash[3]);
	MSG_OUT("- produced hash: %s\n", buf);
	static_cleanup(buf, 71 * sizeof(char));
	static_cleanup(hash, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));
	MSG_OUT("------------------------------------\n");

	return 0;
}
