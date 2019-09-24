#include "./bits/bits_common.h"
#include "./mem/static.h"
#include "./salsa_20_8.h"

void salsa_20_8(uint32_t in[SALSA_20_8_OUTPUT_WORDSIZE], uint32_t out[SALSA_20_8_OUTPUT_WORDSIZE])
{
	size_t i;
	uint32_t x[SALSA_20_8_OUTPUT_WORDSIZE];

	// copy input block -> temporary block
	for (i = 0; i < SALSA_20_8_OUTPUT_WORDSIZE; i++) {
		x[i] = in[i];
	}

	// column and row mixing
	for (i = 0; i < SALSA_20_8_NUM_ROUND; i += 2) {
		x[4]  ^= ROL_32(x[0] + x[12], 7);   x[ 8] ^= ROL_32(x[4] + x[0], 9);
		x[12] ^= ROL_32(x[8] + x[4], 13);   x[ 0] ^= ROL_32(x[12] + x[8], 18);

		x[9] ^= ROL_32(x[5] + x[1], 7);    x[13] ^= ROL_32(x[9] + x[5], 9);
		x[1] ^= ROL_32(x[13] + x[9], 13);  x[5]  ^= ROL_32(x[1] + x[13], 18);

		x[14] ^= ROL_32(x[10] + x[ 6], 7);  x[2]  ^= ROL_32(x[14] + x[10], 9);
		x[6]  ^= ROL_32(x[2] + x[14], 13);  x[10] ^= ROL_32(x[6] + x[ 2], 18);

		x[3]  ^= ROL_32(x[15] + x[11], 7);  x[ 7] ^= ROL_32(x[3] + x[15], 9);
		x[11] ^= ROL_32(x[7] + x[3], 13);   x[15] ^= ROL_32(x[11] + x[7], 18);

		x[1] ^= ROL_32(x[0] + x[3], 7);   x[2] ^= ROL_32(x[1] + x[0], 9);
		x[3] ^= ROL_32(x[2] + x[1], 13);  x[0] ^= ROL_32(x[3] + x[2], 18);

		x[6] ^= ROL_32(x[5] + x[4], 7);   x[7] ^= ROL_32(x[6] + x[5], 9);
		x[4] ^= ROL_32(x[7] + x[6], 13);  x[5] ^= ROL_32(x[4] + x[7], 18);

		x[11] ^= ROL_32(x[10] + x[9], 7);   x[8]  ^= ROL_32(x[11] + x[10], 9);
		x[9]  ^= ROL_32(x[8] + x[11], 13);  x[10] ^= ROL_32(x[9] + x[8], 18);

		x[12] ^= ROL_32(x[15] + x[14], 7);   x[13] ^= ROL_32(x[12] + x[15], 9);
		x[14] ^= ROL_32(x[13] + x[12], 13);  x[15] ^= ROL_32(x[14] + x[13], 18);
	}

	for (i = 0; i < SALSA_20_8_OUTPUT_WORDSIZE; i++)
		out[i] = x[i] + in[i];

	static_cleanup(x, SALSA_20_8_OUTPUT_WORDSIZE * sizeof(uint32_t));
}
