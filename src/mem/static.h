/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#ifndef _STATIC_H_
#define _STATIC_H_

#include <stddef.h>

extern void (* volatile fptr_static_cleanup)(volatile void *, size_t);

static inline void static_cleanup(volatile void *buf, size_t blen)
{
	(fptr_static_cleanup)(buf, blen);
}

#endif /* _STATIC_H_ */
