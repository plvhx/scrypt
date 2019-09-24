/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include <assert.h>
#include <stdio.h>

#include "../src/scrypt.h"
#include "../src/mem/static.h"

// input
uint32_t input[32] = {
	0xf7ce0b65, 0x3d2d72a4, 0x108cf5ab, 0xe912ffdd,
	0x777616db, 0xbb27a70e, 0x8204f3ae, 0x2d0f6fad,
	0x89f68f48, 0x11d1e87b, 0xcc3bd740, 0x0a9ffd29,
	0x094f0184, 0x639574f3, 0x9ae5a131, 0x5217bcd7,
	0x89499144, 0x7213bb22, 0x6c25b54d, 0xa86370fb,
	0xcd984380, 0x374666bb, 0x8ffcb5bf, 0x40c254b0,
	0x67d27c51, 0xce4ad5fe, 0xd829c90b, 0x505a571b,
	0x7f4d1cad, 0x6a523cda, 0x770e67bc, 0xeaaf7e89
};

// output
uint32_t given_rblock[32] = {
	0xa41f859c, 0x6608cc99, 0x3b81cacb, 0x020cef05,
	0x044b2181, 0xa2fd337d, 0xfd7b1c63, 0x96682f29,
	0xb4393168, 0xe3c9e6bc, 0xfe6bc5b7, 0xa06d96ba,
	0xe424cc10, 0x2c91745c, 0x24ad673d, 0xc7618f81,
	0x20edc975, 0x323881a8, 0x0540f64c, 0x162dcd3c,
	0x21077cfe, 0x5f8d5fe2, 0xb1a4168f, 0x953678b7,
	0x7d3b3d80, 0x3b60e4ab, 0x920996e5, 0x9b4d53b6,
	0x5d2a2258, 0x77d5edf5, 0x842cb9f1, 0x4eefe425
};

#define UNUSED(x)	((void)(x))
#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

int main(int argc, char **argv, char **envp)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(envp);

	size_t i, r = 1, c = 0;
	uint32_t rblock[32];

	// revert input to 32-bit little-endian
	for (i = 0; i < 32; i++) {
		input[i] = (((input[i] & 0x000000ff) >>  0) << 24 |
			    ((input[i] & 0x0000ff00) >>  8) << 16 |
			    ((input[i] & 0x00ff0000) >> 16) <<  8 |
			    ((input[i] & 0xff000000) >> 24) <<  0);
	}

	scrypt_block_mix(input, rblock, r);

	// revert generated output to 32-bit little endian
	for (i = 0; i < 32; i++) {
		rblock[i] = (((rblock[i] & 0x000000ff) >>  0) << 24 |
			     ((rblock[i] & 0x0000ff00) >>  8) << 16 |
			     ((rblock[i] & 0x00ff0000) >> 16) <<  8 |
			     ((rblock[i] & 0xff000000) >> 24) <<  0);
	}

	// assert each generated dword with given result dword
	for (i = 0; i < 32; i++) {
		assert(rblock[i] == given_rblock[i]);
	}

	MSG_OUT("B'[0]:\n");
	for (i = 0; i < 16; i += 4) {
		MSG_OUT("0x%08x 0x%08x 0x%08x 0x%08x\n", rblock[i], rblock[i + 1], rblock[i + 2], rblock[i + 3]);
	}
	MSG_OUT("\n");

	MSG_OUT("B'[1]:\n");
	for (; i < 32; i += 4) {
		MSG_OUT("0x%08x 0x%08x 0x%08x 0x%08x\n", rblock[i], rblock[i + 1], rblock[i + 2], rblock[i + 3]);
	}

	static_cleanup(rblock, 32 * sizeof(uint32_t));

	return 0;
}
