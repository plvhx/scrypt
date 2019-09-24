#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../src/hash/sha1.h"

#define UNUSED(x)	((void)(x))

#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

char *given_hash[4] = {
	"a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d",
	"da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709",
	"84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1",
	"a49b2446 a02c645b f419f995 b6709125 3a04a259"
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

	uint32_t hash[5];
	char buf[24];
	sha1_ctx_t ctx;

	MSG_OUT("-----[FIPS SHA-1 Test Vector]-----\n");
	MSG_OUT("test vector #1\n");
	sha1_reset_context(&ctx);
	sha1_update_buf(&ctx, data_vec[0], strlen(data_vec[0]));
	sha1_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3], hash[4]);
	assert(!strcmp(buf, given_hash[0]));
	MSG_OUT("- buf: %s\n", data_vec[0]);
	MSG_OUT("- given hash: %s\n", given_hash[0]);
	MSG_OUT("- produced hash: %s\n\n", buf);

	MSG_OUT("test vector #2\n");
	sha1_reset_context(&ctx);
	sha1_update_buf(&ctx, data_vec[1], strlen(data_vec[1]));
	sha1_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3], hash[4]);
	assert(!strcmp(buf, given_hash[1]));
	MSG_OUT("- buf: %s\n", data_vec[1]);
	MSG_OUT("- given hash: %s\n", given_hash[1]);
	MSG_OUT("- produced hash: %s\n\n", buf);

	MSG_OUT("test vector #3\n");
	sha1_reset_context(&ctx);
	sha1_update_buf(&ctx, data_vec[2], strlen(data_vec[2]));
	sha1_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3], hash[4]);
	assert(!strcmp(buf, given_hash[2]));
	MSG_OUT("- buf: %s\n", data_vec[2]);
	MSG_OUT("- given hash: %s\n", given_hash[2]);
	MSG_OUT("- produced hash: %s\n\n", buf);

	MSG_OUT("test vector #4\n");
	sha1_reset_context(&ctx);
	sha1_update_buf(&ctx, data_vec[3], strlen(data_vec[3]));
	sha1_digest(&ctx, hash);
	sprintf(buf, "%08x %08x %08x %08x %08x", hash[0], hash[1], hash[2], hash[3], hash[4]);
	assert(!strcmp(buf, given_hash[3]));
	MSG_OUT("- buf: %s\n", data_vec[3]);
	MSG_OUT("- given hash: %s\n", given_hash[3]);
	MSG_OUT("- produced hash: %s\n", buf);
	MSG_OUT("----------------------------------\n");

	return 0;
}
