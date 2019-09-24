#include <assert.h>
#include <string.h>

#include "../bits/bits_common.h"
#include "../mem/static.h"
#include "./sha256.h"

void pbkdf2_hmac_sha256(const uint8_t *password, const uint8_t *salt, size_t plen, size_t slen, uint64_t iter_count, size_t dklen, uint8_t *dkbuf)
{
	hmac_sha256_ctx_t ph_ctx, psh_ctx, h_ctx;
	size_t i, j, x, v;
	uint8_t ix[4];
	uint8_t u[SHA256_OUTPUT_BLKSIZE], t[SHA256_OUTPUT_BLKSIZE];
	uint32_t tbuf[SHA256_OUTPUT_WORDSIZE];
	size_t qlen;

	assert(dklen <= SHA256_OUTPUT_BLKSIZE * (size_t)(UINT32_MAX));

	hmac_sha256_init(&ph_ctx, password, plen);
	memcpy(&psh_ctx, &ph_ctx, sizeof(hmac_sha256_ctx_t));
	hmac_sha256_update(&psh_ctx, salt, slen);

	for (i = 0; i * SHA256_OUTPUT_BLKSIZE < dklen; i++) {
		// compute INT(i + 1) in big-endian format.
		ix[3] = (((uint32_t)(i + 1) >>  0) & UINT8_MAX);
		ix[2] = (((uint32_t)(i + 1) >>  8) & UINT8_MAX);
		ix[1] = (((uint32_t)(i + 1) >> 16) & UINT8_MAX);
		ix[0] = (((uint32_t)(i + 1) >> 24) & UINT8_MAX);

		// compute U_1 = PRF(P, S || INT(i + 1))
		memcpy(&h_ctx, &psh_ctx, sizeof(hmac_sha256_ctx_t));
		hmac_sha256_update(&h_ctx, ix, 4);
		hmac_sha256_digest(&h_ctx, tbuf);

		for (j = 0, x = 0; j < SHA256_OUTPUT_WORDSIZE; j++, x += 4) {
			u[x + 0] = (tbuf[j] & 0xff000000) >> 24;
			u[x + 1] = (tbuf[j] & 0x00ff0000) >> 16;
			u[x + 2] = (tbuf[j] & 0x0000ff00) >>  8;
			u[x + 3] = (tbuf[j] & 0x000000ff) >>  0;
		}

		// copy u to t
		memcpy(t, u, SHA256_OUTPUT_BLKSIZE);

		for (j = 2; j <= iter_count; j++) {
			memcpy(&h_ctx, &ph_ctx, sizeof(hmac_sha256_ctx_t));
			hmac_sha256_update(&h_ctx, u, SHA256_OUTPUT_BLKSIZE);
			hmac_sha256_digest(&h_ctx, tbuf);

			for (x = 0, v = 0; x < SHA256_OUTPUT_WORDSIZE; x++, v += 4) {
				u[v + 0] = (tbuf[x] & 0xff000000) >> 24;
				u[v + 1] = (tbuf[x] & 0x00ff0000) >> 16;
				u[v + 2] = (tbuf[x] & 0x0000ff00) >>  8;
				u[v + 3] = (tbuf[x] & 0x000000ff) >>  0;
			}

			for (x = 0; x < SHA256_OUTPUT_BLKSIZE; x++)
				t[x] ^= u[x];
		}

		qlen = dklen - i * SHA256_OUTPUT_BLKSIZE;
		qlen = qlen > SHA256_OUTPUT_BLKSIZE ? SHA256_OUTPUT_BLKSIZE : qlen;
		memcpy(&dkbuf[i * SHA256_OUTPUT_BLKSIZE], t, qlen);
	}

	static_cleanup(ix, 4 * sizeof(uint8_t));
	static_cleanup(u, SHA256_OUTPUT_BLKSIZE * sizeof(uint8_t));
	static_cleanup(t, SHA256_OUTPUT_BLKSIZE * sizeof(uint8_t));
	static_cleanup(tbuf, SHA256_OUTPUT_WORDSIZE * sizeof(uint32_t));
}
