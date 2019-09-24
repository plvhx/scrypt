/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include <string.h>

#include "../bits/bits_common.h"
#include "../mem/static.h"
#include "./sha1.h"

void hmac_sha1_init(hmac_sha1_ctx_t *ctx, const char *buf, size_t blen)
{
	uint32_t hkey[SHA1_OUTPUT_WORDSIZE];
	uint8_t opad[SHA1_BUFFER_BLKSIZE], ipad[SHA1_BUFFER_BLKSIZE];
	uint8_t tbuf[SHA1_OUTPUT_BLKSIZE], *pbuf = (uint8_t *)buf;
	size_t i, j;

	if (blen > SHA1_BUFFER_BLKSIZE) {
		sha1_reset_context(&ctx->in_ctx);
		sha1_update_buf(&ctx->in_ctx, buf, blen);
		sha1_digest(&ctx->in_ctx, hkey);

		for (i = 0, j = 0; i < SHA1_OUTPUT_WORDSIZE; i += 4, j++) {
			tbuf[j + 0] = ((hkey[i] & 0xff000000) >> 24);
			tbuf[j + 1] = ((hkey[i] & 0x00ff0000) >> 16);
			tbuf[j + 2] = ((hkey[i] & 0x0000ff00) >>  8);
			tbuf[j + 3] = ((hkey[i] & 0x000000ff) >>  0);
		}

		pbuf = tbuf;
		blen = SHA1_OUTPUT_BLKSIZE;
	}

	// process inner padding
	sha1_reset_context(&ctx->in_ctx);
	memset(ipad, 0x36, SHA1_BUFFER_BLKSIZE);

	for (i = 0; i < blen; i++) {
		ipad[i] ^= pbuf[i];
	}

	sha1_update_buf(&ctx->in_ctx, (char *)ipad, SHA1_BUFFER_BLKSIZE);

	// process outer padding
	sha1_reset_context(&ctx->out_ctx);
	memset(opad, 0x5c, SHA1_BUFFER_BLKSIZE);

	for (i = 0; i < blen; i++) {
		opad[i] ^= pbuf[i];
	}

	sha1_update_buf(&ctx->out_ctx, (char *)opad, SHA1_BUFFER_BLKSIZE);

	// clean up local variables..
	static_cleanup(hkey, SHA1_OUTPUT_BLKSIZE * sizeof(uint32_t));
	static_cleanup(opad, SHA1_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(ipad, SHA1_OUTPUT_WORDSIZE * sizeof(uint32_t));
	static_cleanup(tbuf, SHA1_BUFFER_BLKSIZE * sizeof(uint8_t));
}

void hmac_sha1_update(hmac_sha1_ctx_t *ctx, const char *buf, size_t blen)
{
	sha1_update_buf(&ctx->in_ctx, buf, blen);
}

void hmac_sha1_digest(hmac_sha1_ctx_t *ctx, uint32_t hash[SHA1_OUTPUT_WORDSIZE])
{
	int i, j;
	char tbuf[SHA1_OUTPUT_BLKSIZE];
	uint32_t wbuf[SHA1_OUTPUT_WORDSIZE];

	sha1_digest(&ctx->in_ctx, wbuf);

	for (i = 0, j = 0; i < SHA1_OUTPUT_WORDSIZE; i++, j += 4) {
		tbuf[j + 0] = ((wbuf[i] & 0xff000000) >> 24);
		tbuf[j + 1] = ((wbuf[i] & 0x00ff0000) >> 16);
		tbuf[j + 2] = ((wbuf[i] & 0x0000ff00) >>  8);
		tbuf[j + 3] = ((wbuf[i] & 0x000000ff) >>  0);
	}

	sha1_update_buf(&ctx->out_ctx, tbuf, SHA1_OUTPUT_BLKSIZE);
	sha1_digest(&ctx->out_ctx, hash);

	// clean up local variables..
	static_cleanup(tbuf, SHA1_OUTPUT_BLKSIZE * sizeof(char));
	static_cleanup(wbuf, SHA1_OUTPUT_WORDSIZE * sizeof(uint32_t));
}
