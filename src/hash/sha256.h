#ifndef _SHA_256_H_
#define _SHA_256_H_

#include <stddef.h>
#include <stdint.h>

#include "../bits/bits_common.h"

#define SHA256_BUFFER_BLKSIZE	64
#define SHA256_OUTPUT_BLKSIZE	32
#define SHA256_OUTPUT_WORDSIZE	(SHA256_OUTPUT_BLKSIZE / 4)

struct sha256_context {
	uint32_t hash[SHA256_OUTPUT_WORDSIZE];
	uint32_t low;
	uint32_t high;
	uint32_t index;
	uint8_t  pbuf[SHA256_BUFFER_BLKSIZE];
};

typedef struct sha256_context sha256_ctx_t;

struct hmac_sha256_context {
	sha256_ctx_t in_ctx;
	sha256_ctx_t out_ctx;
};

typedef struct hmac_sha256_context hmac_sha256_ctx_t;

#define SHA256_S0(x)	(ROR_32((x), 2) ^ ROR_32((x), 13) ^ ROR_32((x), 22))
#define SHA256_S1(x)	(ROR_32((x), 6) ^ ROR_32((x), 11) ^ ROR_32((x), 25))
#define SHA256_CH(x, y, z)	(((x) & (y)) ^ (~(x) & (z)))
#define SHA256_TMP1(a, b, c, d, e)	((a) + (b) + (c) + (d) + (e))
#define SHA256_TMP2(a, b)	((a) + (b))
#define SHA256_MAJOR(a, b, c)	(((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))

// FIPS-180 SHA-256
void sha256_reset_context(sha256_ctx_t *ctx);
void sha256_append_padding(sha256_ctx_t *ctx);
void sha256_process_block(sha256_ctx_t *ctx);
void sha256_digest(sha256_ctx_t *ctx, uint32_t hash[SHA256_OUTPUT_WORDSIZE]);
void sha256_update_buf(sha256_ctx_t *ctx, const uint8_t *buf, size_t blen);

// HMAC SHA-256
void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *buf, size_t blen);
void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const uint8_t *buf, size_t blen);
void hmac_sha256_digest(hmac_sha256_ctx_t *ctx, uint32_t hash[SHA256_OUTPUT_WORDSIZE]);

// PBKDF2 HMAC SHA-256
void pbkdf2_hmac_sha256(const uint8_t *password, const uint8_t *salt, size_t plen, size_t slen, uint64_t iter_count, size_t dklen, uint8_t *dkbuf);

#endif /* _SHA_256_H_ */
