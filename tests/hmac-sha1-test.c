#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../src/hash/sha1.h"
#include "../src/mem/static.h"

#define UNUSED(x)	((void)(x))
#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

char *given_hash[4] = {
	"b6173186 55057264 e28bc0b6 fb378c8e f146be00",
	"effcdf6a e5eb2fa2 d27416d5 f184df9c 259a7c79",
	"125d7342 b9ac11cd 91a39af4 8aa17b4f 63f175d3",
	"4c9007f4 026250c6 bc8414f9 bf50c86c 2d7235da"
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

	uint8_t buf[44];
	uint32_t hash[SHA1_OUTPUT_WORDSIZE];
	hmac_sha1_ctx_t ctx;

	MSG_OUT("-----[HMAC SHA-1 Test Vector]-----\n");
	MSG_OUT("test vector #1\n");
	hmac_sha1_init(&ctx, key_vec[0], strlen(key_vec[0]));
	hmac_sha1_update(&ctx, data_vec[0], strlen(data_vec[0]));
	hmac_sha1_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3], hash[4]);
	assert(!strcmp(buf, given_hash[0]));
	MSG_OUT("- given hash: %s\n", given_hash[0]);
	MSG_OUT("- produced hash: %s\n\n", buf);
	static_cleanup(hash, SHA1_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(buf, 44 * sizeof(uint8_t));

	MSG_OUT("test vector #2\n");
	hmac_sha1_init(&ctx, key_vec[1], strlen(key_vec[1]));
	hmac_sha1_update(&ctx, data_vec[1], strlen(data_vec[1]));
	hmac_sha1_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3], hash[4]);
	assert(!strcmp(buf, given_hash[1]));
	MSG_OUT("- given hash: %s\n", given_hash[1]);
	MSG_OUT("- produced hash: %s\n\n", buf);
	static_cleanup(hash, SHA1_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(buf, 44 * sizeof(uint8_t));

	MSG_OUT("test vector #3\n");
	hmac_sha1_init(&ctx, key_vec[2], strlen(key_vec[2]));
	hmac_sha1_update(&ctx, data_vec[2], strlen(data_vec[2]));
	hmac_sha1_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3], hash[4]);
	assert(!strcmp(buf, given_hash[2]));
	MSG_OUT("- given hash: %s\n", given_hash[2]);
	MSG_OUT("- produced hash: %s\n\n", buf);
	static_cleanup(hash, SHA1_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(buf, 44 * sizeof(uint8_t));

	MSG_OUT("test vector #4\n");
	hmac_sha1_init(&ctx, key_vec[3], strlen(key_vec[3]));
	hmac_sha1_update(&ctx, data_vec[3], strlen(data_vec[3]));
	hmac_sha1_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3], hash[4]);
	assert(!strcmp(buf, given_hash[3]));
	MSG_OUT("- given hash: %s\n", given_hash[3]);
	MSG_OUT("- produced hash: %s\n", buf);
	static_cleanup(hash, SHA1_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(buf, 44 * sizeof(uint8_t));
	MSG_OUT("----------------------------------\n");

	return 0;
}
