/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include "../bits/bits_common.h"
#include "../mem/static.h"
#include "./sha256.h"

static uint32_t sha256_constant_round[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_reset_context(sha256_ctx_t *ctx)
{
	// reset or initialize buffer index
	ctx->index = 0;
	// reset or initialize size
	ctx->low = 0; ctx->high = 0;
	// initialize IV
	ctx->hash[0] = 0x6a09e667; ctx->hash[1] = 0xbb67ae85; ctx->hash[2] = 0x3c6ef372; ctx->hash[3] = 0xa54ff53a;
	ctx->hash[4] = 0x510e527f; ctx->hash[5] = 0x9b05688c; ctx->hash[6] = 0x1f83d9ab; ctx->hash[7] = 0x5be0cd19;
}

void sha256_append_padding(sha256_ctx_t *ctx)
{
	if (ctx->index > 55) {
		ctx->pbuf[ctx->index++] = 0x80;

		while (ctx->index < 64)
			ctx->pbuf[ctx->index++] = 0;

		sha256_process_block(ctx);

		while (ctx->index < 56)
			ctx->pbuf[ctx->index++] = 0;
	} else {
		ctx->pbuf[ctx->index++] = 0x80;

		while (ctx->index < 56)
			ctx->pbuf[ctx->index++] = 0;
	}

	ctx->pbuf[56] = ctx->high >> 24; ctx->pbuf[57] = ctx->high >> 16; ctx->pbuf[58] = ctx->high >> 8; ctx->pbuf[59] = ctx->high;
	ctx->pbuf[60] = ctx->low  >> 24; ctx->pbuf[61] = ctx->low  >> 16; ctx->pbuf[62] = ctx->low  >> 8; ctx->pbuf[63] = ctx->low;

	sha256_process_block(ctx);
}

void sha256_process_block(sha256_ctx_t *ctx)
{
	int t;
	uint32_t tbuf[SHA256_BUFFER_BLKSIZE];
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t _s0, _s1;
	uint32_t _S1, ch, tmp1, _S0, maj, tmp2;

	a = ctx->hash[0]; b = ctx->hash[1]; c = ctx->hash[2]; d = ctx->hash[3];
	e = ctx->hash[4]; f = ctx->hash[5]; g = ctx->hash[6]; h = ctx->hash[7];

	// break chunk into 16 big-endian dword
	for (t = 0; t < 16; t++) {
		tbuf[t] = ((uint32_t)((ctx->pbuf[(t * 4) + 0] & UINT8_MAX) << 24) |
			   (uint32_t)((ctx->pbuf[(t * 4) + 1] & UINT8_MAX) << 16) |
			   (uint32_t)((ctx->pbuf[(t * 4) + 2] & UINT8_MAX) <<  8) |
			   (uint32_t)((ctx->pbuf[(t * 4) + 3] & UINT8_MAX) <<  0));
	}

	// extend the first 16 dword into the remaining 48 words
	for (; t < SHA256_BUFFER_BLKSIZE; t++) {
		_s0 = ROR_32(tbuf[t - 15], 7) ^ ROR_32(tbuf[t - 15], 18) ^ (tbuf[t - 15] >> 3);
		_s1 = ROR_32(tbuf[t - 2], 17) ^ ROR_32(tbuf[t - 2], 19) ^ (tbuf[t - 2] >> 10);
		tbuf[t] = tbuf[t - 16] + _s0 + tbuf[t - 7] + _s1;
	}

	for (t = 0; t < SHA256_BUFFER_BLKSIZE; t++) {
		_S1 = SHA256_S1(e);
		ch = SHA256_CH(e, f, g);
		tmp1 = SHA256_TMP1(h, _S1, ch, sha256_constant_round[t], tbuf[t]);
		_S0 = SHA256_S0(a);
		maj = SHA256_MAJOR(a, b, c);
		tmp2 = SHA256_TMP2(_S0, maj);

		h = g; g = f; f = e; e = d + tmp1; d = c;
		c = b; b = a; a = tmp1 + tmp2;
	}

	ctx->hash[0] += a; ctx->hash[1] += b; ctx->hash[2] += c; ctx->hash[3] += d;
	ctx->hash[4] += e; ctx->hash[5] += f; ctx->hash[6] += g; ctx->hash[7] += h;
	ctx->index = 0;

	// clean up local variables
	static_cleanup(tbuf, SHA256_BUFFER_BLKSIZE * sizeof(uint32_t));
}

void sha256_digest(sha256_ctx_t *ctx, uint32_t hash[SHA256_OUTPUT_WORDSIZE])
{
	int i;

	sha256_append_padding(ctx);

	// zero buffer
	for (i = 0; i < SHA256_BUFFER_BLKSIZE; i++)
		ctx->pbuf[i] = 0;

	// restore low and high state
	ctx->low = 0; ctx->high = 0;

	for (i = 0; i < SHA256_OUTPUT_WORDSIZE; i++) {
		hash[i] = ctx->hash[i];
	}
}

void sha256_update_buf(sha256_ctx_t *ctx, const uint8_t *buf, size_t blen)
{
	const uint8_t *pbuf = (const uint8_t *)buf;

	while (blen--) {
		ctx->pbuf[ctx->index++] = (uint8_t)(*pbuf & UINT8_MAX);
		ctx->low += 8; ctx->high = !ctx->low ? ctx->high + 1 : ctx->high;

		if (ctx->index == SHA256_BUFFER_BLKSIZE)
			sha256_process_block(ctx);

		pbuf++;
	}
}
