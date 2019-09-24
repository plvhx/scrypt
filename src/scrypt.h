/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#ifndef _SCRYPT_H_
#define _SCRYPT_H_

#include <stdint.h>
#include <stddef.h>

#ifndef __set_errno
#define __set_errno(e)	((errno) = (e))
#endif

void scrypt_block_mix(uint32_t *in, uint32_t *out, size_t r);
void scrypt_romix(size_t r, uint64_t N, uint8_t *in, void *v, void *xy);
int crypto_scrypt_kdf(const uint8_t *password, const uint8_t *salt, size_t plen, size_t slen, uint64_t N, uint32_t r, uint32_t p, uint8_t *buf, size_t blen);

#endif /* _SCRYPT_H_ */
