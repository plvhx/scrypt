/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#ifndef _SALSA_20_8_H_
#define _SALSA_20_8_H_

#include <stdint.h>

#define SALSA_20_8_OUTPUT_WORDSIZE	16
#define SALSA_20_8_NUM_ROUND	8

void salsa_20_8(uint32_t in[SALSA_20_8_OUTPUT_WORDSIZE], uint32_t out[SALSA_20_8_OUTPUT_WORDSIZE]);

#endif /* _SALSA_20_8_H_ */
