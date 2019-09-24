#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../src/mem/static.h"
#include "../src/hash/sha256.h"

#define UNUSED(x)	((void)(x))

#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

char *given_hash[4] = {
	"ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",
	"e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855",
	"248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1",
	"cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1"
};

char *data_vec[4] = {
	"abc",
	"",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
};

int main(int argc, char **argv, char **envp)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(envp);

	uint32_t hash[SHA256_OUTPUT_WORDSIZE];
	char buf[71];
	sha256_ctx_t ctx;

	MSG_OUT("-----[FIPS SHA-256 Test Vector]-----\n");
	MSG_OUT("test vector #1\n");
	sha256_reset_context(&ctx);
	sha256_update_buf(&ctx, data_vec[0], strlen(data_vec[0]));
	sha256_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3],
		hash[4], hash[5], hash[6], hash[7]);
	assert(!strcmp(buf, given_hash[0]));
	MSG_OUT("- buf: %s\n", data_vec[0]);
	MSG_OUT("- given hash: %s\n", given_hash[0]);
	MSG_OUT("- produced hash: %s\n\n", buf);
	static_cleanup(hash, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(buf, 71 * sizeof(char));

	MSG_OUT("test vector #2\n");
	sha256_reset_context(&ctx);
	sha256_update_buf(&ctx, data_vec[1], strlen(data_vec[1]));
	sha256_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3],
		hash[4], hash[5], hash[6], hash[7]);
	assert(!strcmp(buf, given_hash[1]));
	MSG_OUT("- buf: %s\n", data_vec[1]);
	MSG_OUT("- given hash: %s\n", given_hash[1]);
	MSG_OUT("- produced hash: %s\n\n", buf);
	static_cleanup(hash, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(buf, 71 * sizeof(char));

	MSG_OUT("test vector #3\n");
	sha256_reset_context(&ctx);
	sha256_update_buf(&ctx, data_vec[2], strlen(data_vec[2]));
	sha256_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3],
		hash[4], hash[5], hash[6], hash[7]);
	assert(!strcmp(buf, given_hash[2]));
	MSG_OUT("- buf: %s\n", data_vec[2]);
	MSG_OUT("- given hash: %s\n", given_hash[2]);
	MSG_OUT("- produced hash: %s\n\n", buf);
	static_cleanup(hash, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(buf, 71 * sizeof(char));

	MSG_OUT("test vector #4\n");
	sha256_reset_context(&ctx);
	sha256_update_buf(&ctx, data_vec[3], strlen(data_vec[3]));
	sha256_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3],
		hash[4], hash[5], hash[6], hash[7]);
	assert(!strcmp(buf, given_hash[3]));
	MSG_OUT("- buf: %s\n", data_vec[3]);
	MSG_OUT("- given hash: %s\n", given_hash[3]);
	MSG_OUT("- produced hash: %s\n", buf);
	static_cleanup(hash, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(buf, 71 * sizeof(char));
	MSG_OUT("------------------------------------\n");

	return 0;
}
