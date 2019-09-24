/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include <string.h>

#include "../bits/bits_common.h"
#include "../mem/static.h"
#include "./sha256.h"

void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *buf, size_t blen)
{
	uint32_t hkey[SHA256_OUTPUT_WORDSIZE];
	uint8_t opad[SHA256_BUFFER_BLKSIZE], ipad[SHA256_BUFFER_BLKSIZE];
	uint8_t tbuf[SHA256_OUTPUT_BLKSIZE];
	const uint8_t *pbuf = (const uint8_t *)buf;
	size_t i, j;

	if (blen > SHA256_BUFFER_BLKSIZE) {
		sha256_reset_context(&ctx->in_ctx);
		sha256_update_buf(&ctx->in_ctx, buf, blen);
		sha256_digest(&ctx->in_ctx, hkey);

		for (i = 0, j = 0; i < SHA256_OUTPUT_WORDSIZE; i += 4, j++) {
			tbuf[j + 0] = ((hkey[i] & 0xff000000) >> 24);
			tbuf[j + 1] = ((hkey[i] & 0x00ff0000) >> 16);
			tbuf[j + 2] = ((hkey[i] & 0x0000ff00) >>  8);
			tbuf[j + 3] = ((hkey[i] & 0x000000ff) >>  0);
		}

		pbuf = tbuf;
		blen = SHA256_OUTPUT_BLKSIZE;
	}

	// process inner padding
	sha256_reset_context(&ctx->in_ctx);
	memset(ipad, 0x36, SHA256_BUFFER_BLKSIZE);

	for (i = 0; i < blen; i++)
		ipad[i] ^= pbuf[i];

	sha256_update_buf(&ctx->in_ctx, ipad, SHA256_BUFFER_BLKSIZE);

	// process outer padding
	sha256_reset_context(&ctx->out_ctx);
	memset(opad, 0x5c, SHA256_BUFFER_BLKSIZE);

	for (i = 0; i < blen; i++)
		opad[i] ^= pbuf[i];

	sha256_update_buf(&ctx->out_ctx, opad, SHA256_BUFFER_BLKSIZE);

	// clean up local variables..
	static_cleanup(hkey, SHA256_OUTPUT_BLKSIZE * sizeof(uint32_t));
	static_cleanup(opad, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(ipad, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(tbuf, SHA256_BUFFER_BLKSIZE * sizeof(uint8_t));
}

void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const uint8_t *buf, size_t blen)
{
	sha256_update_buf(&ctx->in_ctx, buf, blen);
}

void hmac_sha256_digest(hmac_sha256_ctx_t *ctx, uint32_t hash[SHA256_OUTPUT_WORDSIZE])
{
	int i, j;
	uint8_t tbuf[SHA256_OUTPUT_BLKSIZE];
	uint32_t wbuf[SHA256_OUTPUT_WORDSIZE];

	// finish inner padding context..
	sha256_digest(&ctx->in_ctx, wbuf);

	for (i = 0, j = 0; i < SHA256_OUTPUT_WORDSIZE; i++, j += 4) {
		tbuf[j + 0] = ((wbuf[i] & 0xff000000) >> 24);
		tbuf[j + 1] = ((wbuf[i] & 0x00ff0000) >> 16);
		tbuf[j + 2] = ((wbuf[i] & 0x0000ff00) >>  8);
		tbuf[j + 3] = ((wbuf[i] & 0x000000ff) >>  0);
	}

	// finish outer padding context..
	sha256_update_buf(&ctx->out_ctx, tbuf, SHA256_OUTPUT_BLKSIZE);
	sha256_digest(&ctx->out_ctx, hash);

	// clean up local variables..
	static_cleanup(tbuf, SHA256_OUTPUT_BLKSIZE * sizeof(uint8_t));
	static_cleanup(wbuf, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));
}
