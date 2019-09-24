/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include "./scrypt.h"
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

static uint64_t integerify(const void *vbuf, size_t r)
{
	const uint32_t *tmp = (const void *)((uintptr_t)(vbuf) + (2 * r - 1) * 64);
	return (((uint64_t)(tmp[1]) << 32) + tmp[0]);
}

static inline void LE32_ENC(void *ptr, uint32_t q)
{
	uint8_t *pptr = (uint8_t *)ptr;

	pptr[0] = (q >>  0) & 0xff;
	pptr[1] = (q >>  8) & 0xff;
	pptr[2] = (q >> 16) & 0xff;
	pptr[3] = (q >> 24) & 0xff;
}

static inline uint32_t LE32_DEC(const void *ptr)
{
	const uint8_t *pptr = (const uint8_t *)ptr;

	return ((uint32_t)(pptr[0]) + (uint32_t)(pptr[1] << 8) + (uint32_t)(pptr[2] << 16) + (uint32_t)(pptr[3] << 24));
}

void scrypt_romix(size_t r, uint64_t N, uint8_t *in, void *v, void *xy)
{
	uint32_t *x = xy;
	uint32_t *y = (void *)((uint8_t *)(xy) + 128 * r);
	uint32_t *nv = v;
	uint64_t i, j;
	size_t k;

	/* 1. X = B */
	for (k = 0; k < 32 * r; k++)
		x[k] = LE32_DEC(&in[4 * k]);

	/* 2. for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 2a. V[i] = X */
		blkcpy(&nv[i * (32 * r)], x, 128 * r);

		/* 2b. X = scryptBlockMix (X) */
		scrypt_block_mix(x, y, r);

		/* 2a. V[i] = X */
		blkcpy(&nv[(i + 1) * (32 * r)], y, 128 * r);

		/* 2b. X = scryptBlockMix (X) */
		scrypt_block_mix(y, x, r);
	}

	/* 3. for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 3a. j = Integerify (X) mod N */
		j = integerify(x, r) & (N - 1);

		/* 3b. T = X xor V[j] */
		blkxor(x, &nv[j * (32 * r)], 128 * r);
		scrypt_block_mix(x, y, r);

		/* 3a. j = Integerify (X) mod N */
		j = integerify(y, r) & (N - 1);

		/* 3b. T = X xor V[j] */
		blkxor(y, &nv[j * (32 * r)], 128 * r);
		scrypt_block_mix(y, x, r);
	}

	/* 4. B' = X */
	for (k = 0; k < 32 * r; k++) {
		LE32_ENC(&in[4 * k], x[k]);
	}
}
