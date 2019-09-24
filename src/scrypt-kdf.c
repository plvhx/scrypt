#include <errno.h>
#include <stdlib.h>

#include "./hash/sha256.h"
#include "./mem/static.h"
#include "./scrypt.h"

static void blkzero(void *p, size_t len)
{
	size_t *pp = (size_t *)p;
	size_t _len = len / sizeof(size_t);
	size_t i;

	for (i = 0; i < _len; i++)
		pp[i] = 0;
}

int crypto_scrypt_kdf(const uint8_t *password, const uint8_t *salt, size_t plen, size_t slen, uint64_t N, uint32_t r, uint32_t p, uint8_t *buf, size_t blen)
{
	void *b0, *v0, *xy0;
	uint8_t *b;
	uint32_t *v;
	uint32_t *xy;
	size_t nr = r, np = p;
	uint32_t i;

#if SIZE_MAX > UINT32_MAX
	if (blen > (((uint64_t)(1) << 32) - 1) * 32) {
		__set_errno(EFBIG);
		goto e0;
	}
#endif

	if ((uint64_t)(nr) * (uint64_t)(np) >= (1 << 30)) {
		__set_errno(EFBIG);
		goto e0;
	}

	if (((N & (N - 1)) != 0) || (N < 2)) {
		__set_errno(EINVAL);
		goto e0;
	}

	if ((nr > SIZE_MAX / 128 / np) ||
#if SIZE_MAX / 256 <= UINT32_MAX
	    (nr > (SIZE_MAX - 64) / 256) ||
#endif
	    (N > SIZE_MAX / 128 / nr)) {
		__set_errno(ENOMEM);
		goto e0;
	}

	// try using posix_memalign
#ifdef HAVE_POSIX_MEMALIGN
	if (__set_errno(posix_memalign(&b0, 64, 128 * nr * np)) != 0)
		goto e0;

	b = (uint8_t *)b0;

	if (__set_errno(posix_memalign(&xy0, 64, 256 * nr + 64)) != 0)
		goto e0;

	xy = (uint32_t *)(xy0);
#if !defined(MAP_ANON) || !defined(HAVE_MMAP)
	if (__set_errno(posix_memalign(&v0, 64, (size_t)(128 * nr * N))) != 0)
		goto e2;

	v = (uint32_t *)v0;
#endif
	// try using malloc
#else
	if ((b0 = malloc(128 * nr * np + 63)) == NULL)
		goto e0;

	b = (uint8_t *)(((uintptr_t)(b0) + 63) & ~(uintptr_t)(63));

	if ((xy0 = malloc(256 * nr + 64 + 63)) == NULL)
		goto e1;

	xy = (uint32_t *)(((uintptr_t)(xy0) + 63) & ~(uintptr_t)(63));
#if !defined(MAP_ANON) || !defined(HAVE_MMAP)
	if ((v0 = malloc(128 * nr * N + 63)) == NULL)
		goto e2;

	v = (uint32_t *)(((uintptr_t)(v0) + 63) & ~(uintptr_t)(63));
#endif
#endif
	// try using mmap() syscall
#if defined(MAP_ANON) && defined(HAVE_MMAP)
	if ((v0 = mmap(NULL, (size_t)(128 * nr * N), PROT_READ | PROT_WRITE,
#if MAP_NOCORE	// freebsd :)
	MAP_ANON | MAP_PRIVATE | MAP_NOCORE,
#else
	MAP_ANON | MAP_PRIVATE,
#endif
	-1, 0)) == MAP_FAILED)
		goto e2;

	v = (uint32_t *)v0;
#endif

	// zero allocated buffer.
	blkzero(b, np * 128 * nr * sizeof(uint8_t));

	// 1. B[0] || B[1] || ... || B[p - 1] = PBKDF2-HMAC-SHA256 (P, S, 1, p * 128 * r)
	pbkdf2_hmac_sha256(password, salt, plen, slen, 1, np * 128 * nr, b);

	// 2. for i = 0 to p - 1 do
	for (i = 0; i < np; i++) {
		scrypt_romix(nr, N, &b[i * 128 * nr], v, xy);
	}

	// 3. DK = PBKDF2-HMAC-SHA256 (P, B[0] || B[1] || ... || B[p - 1], 1, dkLen)
	pbkdf2_hmac_sha256(password, b, plen, np * 128 * nr, 1, blen, buf);

#if defined(MAP_ANON) && defined(HAVE_MMAP)
	if (munmap(v0, (size_t)(128 * nr * N)))
		goto e2;
#else
	free(v0);
#endif

	free(xy0);
	free(b0);

	return 0;

e2:
	free(xy0);
e1:
	free(b0);
e0:
	return -1;
}
