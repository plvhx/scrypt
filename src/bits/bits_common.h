/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#ifndef _BITS_COMMON_H_
#define _BITS_COMMON_H_

// rotate left
#define ROL_32(x, i)	(((x) << (i)) | ((x) >> (32 - (i))))
#define ROL_64(x, i)	(((x) << (i)) | ((x) >> (64 - (i))))

// rotate right
#define ROR_32(x, i)	(((x) >> (i)) | ((x) << (32 - (i))))
#define ROR_64(x, i)	(((x) >> (i)) | ((x) << (64 - (i))))

#endif /* _BITS_COMMON_H_ */
