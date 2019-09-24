/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#ifndef _SHA_1_H_
#define _SHA_1_H_

#include <stddef.h>
#include <stdint.h>

#define SHA1_BUFFER_BLKSIZE	64
#define SHA1_OUTPUT_BLKSIZE	20
#define SHA1_OUTPUT_WORDSIZE	(SHA1_OUTPUT_BLKSIZE / 4)

struct sha1_context {
	uint32_t hash[SHA1_OUTPUT_WORDSIZE];
	uint32_t low;
	uint32_t high;
	uint32_t index;
	uint8_t  pbuf[SHA1_BUFFER_BLKSIZE];
};

typedef struct sha1_context sha1_ctx_t;

struct hmac_sha1_context {
	sha1_ctx_t in_ctx;
	sha1_ctx_t out_ctx;
};

typedef struct hmac_sha1_context hmac_sha1_ctx_t;

#define SHA1_BITS_F(x, y, z)	(((x) & (y)) | (~(x) & (z)))
#define SHA1_BITS_G(x, y, z)	((x) ^ (y) ^ (z))
#define SHA1_BITS_H(x, y, z)	(((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define SHA1_BITS_I(x, y, z)	((x) ^ (y) ^ (z))

// FIPS-180 SHA-1
void sha1_reset_context(sha1_ctx_t *ctx);
void sha1_append_padding(sha1_ctx_t *ctx);
void sha1_process_block(sha1_ctx_t *ctx);
void sha1_digest(sha1_ctx_t *ctx, uint32_t hash[SHA1_OUTPUT_WORDSIZE]);
void sha1_update_buf(sha1_ctx_t *ctx, const char *buf, size_t len);

// HMAC SHA-1
void hmac_sha1_init(hmac_sha1_ctx_t *ctx, const char *buf, size_t blen);
void hmac_sha1_update(hmac_sha1_ctx_t *ctx, const char *buf, size_t blen);
void hmac_sha1_digest(hmac_sha1_ctx_t *ctx, uint32_t hash[SHA1_OUTPUT_WORDSIZE]);

// PBKDF2 HMAC SHA-1
void pbkdf2_hmac_sha1(const char *password, const char *salt, size_t plen, size_t slen, uint64_t iter_count, size_t dklen, uint8_t *dkbuf);

#endif /* _SHA_1_H_ */
