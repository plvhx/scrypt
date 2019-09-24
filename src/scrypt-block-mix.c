/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include "./scrypt.h"
#include "./salsa_20_8.h"
#include "./mem/static.h"

static void blkcpy(void *dest, const void *src, size_t len)
{
	size_t *_dest = dest;
	const size_t *_src = src;
	size_t _len = len / sizeof(size_t);
	size_t i;

	for (i = 0; i < _len; i++)
		_dest[i] = _src[i];
}

static void blkxor(void *dest, const void *src, size_t len)
{
	size_t *_dest = dest;
	const size_t *_src = src;
	size_t _len = len / sizeof(size_t);
	size_t i;

	for (i = 0; i < _len; i++)
		_dest[i] ^= _src[i];
}

void scrypt_block_mix(uint32_t *in, uint32_t *out, size_t r)
{
        uint32_t tmp[SALSA_20_8_OUTPUT_WORDSIZE], otmp[SALSA_20_8_OUTPUT_WORDSIZE];
        size_t i;

        // 1. X = B[2 * r - 1]
        blkcpy(tmp, &in[(2 * r - 1) * 16], 64);

        // 2. for i = 0 to 2 * r - 1 do
        for (i = 0; i < 2 * r; i += 2) {
                // 3. T = X xor B[i]
		blkxor(tmp, &in[i * 16], 64);
		salsa_20_8(tmp, otmp);

		// 4. Y[i] = X
		// 6.  B' = (Y[0], Y[2], ..., Y[2 * r - 2], Y[1], Y[3], ..., Y[2 * r - 1])
		blkcpy(&out[i * 8], otmp, 64);

		// 3. T = X xor B[i]
		blkxor(otmp, &in[i * 16 + 16], 64);
		blkcpy(tmp, otmp, 64);
		salsa_20_8(tmp, otmp);

		// 4. Y[i] = X
        // 6.  B' = (Y[0], Y[2], ..., Y[2 * r - 2], Y[1], Y[3], ..., Y[2 * r - 1])
		blkcpy(&out[i * 8 + r * 16], otmp, 64);
		blkcpy(tmp, otmp, 64);
	}

	static_cleanup(tmp, SALSA_20_8_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(otmp, SALSA_20_8_OUTPUT_WORDSIZE * sizeof(uint32_t));
}
