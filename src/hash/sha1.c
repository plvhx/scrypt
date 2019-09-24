/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include "../bits/bits_common.h"
#include "../mem/static.h"
#include "./sha1.h"

void sha1_reset_context(sha1_ctx_t *ctx)
{
	// reset or initialize buffer index
	ctx->index = 0;
	// reset or initialize size
	ctx->low = 0; ctx->high = 0;
	// reset or initialize IV
	ctx->hash[0] = 0x67452301; ctx->hash[1] = 0xEFCDAB89; ctx->hash[2] = 0x98BADCFE;
	ctx->hash[3] = 0x10325476; ctx->hash[4] = 0xC3D2E1F0;
}

void sha1_append_padding(sha1_ctx_t *ctx)
{
	if (ctx->index > 55) {
		ctx->pbuf[ctx->index++] = 0x80;

		while (ctx->index < 64)
			ctx->pbuf[ctx->index++] = 0;

		sha1_process_block(ctx);

		while (ctx->index < 56)
			ctx->pbuf[ctx->index++] = 0;
	} else {
		ctx->pbuf[ctx->index++] = 0x80;

		while (ctx->index < 56)
			ctx->pbuf[ctx->index++] = 0;
	}

	ctx->pbuf[56] = ctx->high >> 24; ctx->pbuf[57] = ctx->high >> 16; ctx->pbuf[58] = ctx->high >> 8; ctx->pbuf[59] = ctx->high;
	ctx->pbuf[60] = ctx->low  >> 24; ctx->pbuf[61] = ctx->low  >> 16; ctx->pbuf[62] = ctx->low  >> 8; ctx->pbuf[63] = ctx->low;

	sha1_process_block(ctx);
}

void sha1_process_block(sha1_ctx_t *ctx)
{
	int t;
	uint32_t tmp;
	uint32_t tbuf[80];
	uint32_t a, b, c, d, e, f, k;

	a = ctx->hash[0]; b = ctx->hash[1]; c = ctx->hash[2];
	d = ctx->hash[3]; e = ctx->hash[4];

	// break chunk into 16 big-endian dword
	for (t = 0; t < 16; t++) {
		tbuf[t] = ((uint32_t)((ctx->pbuf[(t * 4) + 0] & UINT8_MAX) << 24) |
			   (uint32_t)((ctx->pbuf[(t * 4) + 1] & UINT8_MAX) << 16) |
			   (uint32_t)((ctx->pbuf[(t * 4) + 2] & UINT8_MAX) <<  8) |
			   (uint32_t)((ctx->pbuf[(t * 4) + 3] & UINT8_MAX) <<  0));
	}

	// extend the 16 dword into 80 dword
	for (; t < 80; t++) {
		tbuf[t] = ROL_32(tbuf[t - 3] ^ tbuf[t - 8] ^ tbuf[t - 14] ^ tbuf[t - 16], 1);
	}

	for (t = 0; t < 80; t++) {
		if (t >= 0 && t <= 19) {
			f = SHA1_BITS_F(b, c, d);
			k = 0x5A827999;
		} else if (t >= 20 && t <= 39) {
			f = SHA1_BITS_G(b, c, d);
			k = 0x6ED9EBA1;
		} else if (t >= 40 && t <= 59) {
			f = SHA1_BITS_H(b, c, d);
			k = 0x8F1BBCDC;
		} else if (t >= 60 && t <= 79) {
			f = SHA1_BITS_I(b, c, d);
			k = 0xCA62C1D6;
		}

		tmp = ROL_32(a, 5) + f + e + k + tbuf[t];
		e = d;
		d = c;
		c = ROL_32(b, 30);
		b = a;
		a = tmp;
	}

	ctx->hash[0] += a; ctx->hash[1] += b; ctx->hash[2] += c;
	ctx->hash[3] += d; ctx->hash[4] += e; ctx->index = 0;

	// clean up local variables.
	static_cleanup(tbuf, 80 * sizeof(uint32_t));
}

void sha1_digest(sha1_ctx_t *ctx, uint32_t hash[SHA1_OUTPUT_WORDSIZE])
{
	int i;

	sha1_append_padding(ctx);

	// zero buffer
	for (i = 0; i < 64; i++) {
		ctx->pbuf[i] = 0;
	}

	// restore low and high state
	ctx->low = 0; ctx->high = 0;

	for (i = 0; i < SHA1_OUTPUT_WORDSIZE; i++) {
		hash[i] = ctx->hash[i];
	}
}

void sha1_update_buf(sha1_ctx_t *ctx, const char *buf, size_t blen)
{
	uint8_t *pbuf = (uint8_t *)buf;

	while (blen--) {
		ctx->pbuf[ctx->index++] = (uint8_t)(*pbuf & UINT8_MAX);
		ctx->low += 8; ctx->high = !ctx->low ? ctx->high + 1 : ctx->high;

		if (ctx->index == SHA1_BUFFER_BLKSIZE)
			sha1_process_block(ctx);

		pbuf++;
	}
}
