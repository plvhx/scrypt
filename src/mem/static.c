/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include "./static.h"

#include <stdint.h>

static void __internal_static_cleanup(volatile void *buf, size_t blen)
{
	volatile uint8_t *pbuf = buf;
	size_t i;

	for (i = 0; i < blen; i++)
		pbuf[i] = 0;
}

void (* volatile fptr_static_cleanup)(volatile void *, size_t) = __internal_static_cleanup;
