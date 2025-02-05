/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/mem/static.h"
#include "../src/scrypt.h"

#define UNUSED(x)	((void)(x))
#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

uint8_t input[128] = {
	0xf7, 0xce, 0x0b, 0x65, 0x3d, 0x2d, 0x72, 0xa4, 0x10, 0x8c, 0xf5, 0xab, 0xe9, 0x12, 0xff, 0xdd,
	0x77, 0x76, 0x16, 0xdb, 0xbb, 0x27, 0xa7, 0x0e, 0x82, 0x04, 0xf3, 0xae, 0x2d, 0x0f, 0x6f, 0xad,
	0x89, 0xf6, 0x8f, 0x48, 0x11, 0xd1, 0xe8, 0x7b, 0xcc, 0x3b, 0xd7, 0x40, 0x0a, 0x9f, 0xfd, 0x29,
	0x09, 0x4f, 0x01, 0x84, 0x63, 0x95, 0x74, 0xf3, 0x9a, 0xe5, 0xa1, 0x31, 0x52, 0x17, 0xbc, 0xd7,
	0x89, 0x49, 0x91, 0x44, 0x72, 0x13, 0xbb, 0x22, 0x6c, 0x25, 0xb5, 0x4d, 0xa8, 0x63, 0x70, 0xfb,
	0xcd, 0x98, 0x43, 0x80, 0x37, 0x46, 0x66, 0xbb, 0x8f, 0xfc, 0xb5, 0xbf, 0x40, 0xc2, 0x54, 0xb0,
	0x67, 0xd2, 0x7c, 0x51, 0xce, 0x4a, 0xd5, 0xfe, 0xd8, 0x29, 0xc9, 0x0b, 0x50, 0x5a, 0x57, 0x1b,
	0x7f, 0x4d, 0x1c, 0xad, 0x6a, 0x52, 0x3c, 0xda, 0x77, 0x0e, 0x67, 0xbc, 0xea, 0xaf, 0x7e, 0x89
};

uint8_t given_output[128] = {
	0x79, 0xcc, 0xc1, 0x93, 0x62, 0x9d, 0xeb, 0xca, 0x04, 0x7f, 0x0b, 0x70, 0x60, 0x4b, 0xf6, 0xb6,
	0x2c, 0xe3, 0xdd, 0x4a, 0x96, 0x26, 0xe3, 0x55, 0xfa, 0xfc, 0x61, 0x98, 0xe6, 0xea, 0x2b, 0x46,
	0xd5, 0x84, 0x13, 0x67, 0x3b, 0x99, 0xb0, 0x29, 0xd6, 0x65, 0xc3, 0x57, 0x60, 0x1f, 0xb4, 0x26,
	0xa0, 0xb2, 0xf4, 0xbb, 0xa2, 0x00, 0xee, 0x9f, 0x0a, 0x43, 0xd1, 0x9b, 0x57, 0x1a, 0x9c, 0x71,
	0xef, 0x11, 0x42, 0xe6, 0x5d, 0x5a, 0x26, 0x6f, 0xdd, 0xca, 0x83, 0x2c, 0xe5, 0x9f, 0xaa, 0x7c,
	0xac, 0x0b, 0x9c, 0xf1, 0xbe, 0x2b, 0xff, 0xca, 0x30, 0x0d, 0x01, 0xee, 0x38, 0x76, 0x19, 0xc4,
	0xae, 0x12, 0xfd, 0x44, 0x38, 0xf2, 0x03, 0xa0, 0xe4, 0xe1, 0xc4, 0x7e, 0xc3, 0x14, 0x86, 0x1f,
	0x4e, 0x90, 0x87, 0xcb, 0x33, 0x39, 0x6a, 0x68, 0x73, 0xe8, 0xf9, 0xd2, 0x53, 0x9a, 0x4b, 0x8e
};

int main(int argc, char **argv, char **envp)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(envp);

	uint8_t *v;
	uint8_t *xy;
	size_t r = 1;
	uint64_t N = 16;
	size_t i, c = 0;

	v = malloc(128 * r * N);
	xy = malloc(256 * r + 64);

	MSG_OUT("input:\n");
	for (i = 0; i < r * 128; i += 16) {
                MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        input[i + 0], input[i + 1], input[i + 2], input[i + 3], input[i + 4],
                        input[i + 5], input[i + 6], input[i + 7], input[i + 8], input[i + 9],
                        input[i + 10], input[i + 11], input[i + 12], input[i + 13], input[i + 14],
                        input[i + 15]);
        }
	MSG_OUT("\n");

	scrypt_romix(r, N, input, v, xy);

	for (i = 0; i < r * 128; i++) {
		assert(input[i] == given_output[i]);
	}

	MSG_OUT("output:\n");
	for (i = 0; i < r * 128; i += 16) {
		MSG_OUT("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			input[i + 0], input[i + 1], input[i + 2], input[i + 3], input[i + 4],
			input[i + 5], input[i + 6], input[i + 7], input[i + 8], input[i + 9],
			input[i + 10], input[i + 11], input[i + 12], input[i + 13], input[i + 14],
			input[i + 15]);
	}

	free(xy);
	free(v);

	return 0;
}
