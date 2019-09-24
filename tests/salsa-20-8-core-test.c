/**
 * @author Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>

#include "../src/salsa_20_8.h"
#include "../src/mem/static.h"

// output
uint32_t test_vec[SALSA_20_8_OUTPUT_WORDSIZE] = {
	0xa41f859c, 0x6608cc99, 0x3b81cacb, 0x020cef05,
	0x044b2181, 0xa2fd337d, 0xfd7b1c63, 0x96682f29,
	0xb4393168, 0xe3c9e6bc, 0xfe6bc5b7, 0xa06d96ba,
	0xe424cc10, 0x2c91745c, 0x24ad673d, 0xc7618f81
};

// input
uint32_t in_vec[SALSA_20_8_OUTPUT_WORDSIZE] = {
	0x7e879a21, 0x4f3ec986, 0x7ca940e6, 0x41718f26,
	0xbaee555b, 0x8c61c1b5, 0x0df84611, 0x6dcd3b1d,
	0xee24f319, 0xdf9b3d85, 0x14121e4b, 0x5ac5aa32,
	0x76021d29, 0x09c74829, 0xedebc68d, 0xb8b8c25e
};

#define UNUSED(x)	((void)(x))
#define MSG_OUT(...)	fprintf(stdout, __VA_ARGS__)
#define MSG_ERR(...)	fprintf(stderr, __VA_ARGS__)

int main(int argc, char **argv, char **envp)
{
	uint32_t wbuf[SALSA_20_8_OUTPUT_WORDSIZE];
	size_t i, c = 0;

	// revert each input dword to big-endian
	for (i = 0; i < SALSA_20_8_OUTPUT_WORDSIZE; i++) {
		in_vec[i] = (uint32_t)(((in_vec[i] & 0x000000ff) >> 0) << 24 |
			((in_vec[i] & 0x0000ff00) >> 8)  << 16 |
			((in_vec[i] & 0x00ff0000) >> 16) <<  8 |
			((in_vec[i] & 0xff000000) >> 24) <<  0);
	}

	salsa_20_8(in_vec, wbuf);

	// revert each output dword to big-endian
	for (i = 0; i < SALSA_20_8_OUTPUT_WORDSIZE; i++) {
                wbuf[i] = (uint32_t)(((wbuf[i] & 0x000000ff) >> 0) << 24 |
                        ((wbuf[i] & 0x0000ff00) >> 8)  << 16 |
                        ((wbuf[i] & 0x00ff0000) >> 16) <<  8 |
                        ((wbuf[i] & 0xff000000) >> 24) <<  0);
        }

	MSG_OUT("----[SALSA 20/8 core test vector]----\n");
	// do assertions..
	for (i = 0; i < SALSA_20_8_OUTPUT_WORDSIZE; i++) {
		assert(wbuf[i] == test_vec[i]);
	}

	// print given input
	MSG_OUT("- given input:\n");
        for (i = 0; i < SALSA_20_8_OUTPUT_WORDSIZE; i++) {
                if (c != 4) {
                        MSG_OUT("%02x %02x %02x %02x ",
                                (in_vec[i] & 0x000000ff) >>  0,
                                (in_vec[i] & 0x0000ff00) >>  8,
                                (in_vec[i] & 0x00ff0000) >> 16,
                                (in_vec[i] & 0xff000000) >> 24
                        );

                        c++;
                } else if (c == 4) {
                        MSG_OUT("\n");
                        c = 0;
                }
        }
        MSG_OUT("\n");

	c = 0;

	// print given output
	MSG_OUT("- given output:\n");
	for (i = 0; i < SALSA_20_8_OUTPUT_WORDSIZE; i++) {
		if (c != 4) {
			MSG_OUT("%02x %02x %02x %02x ",
				(test_vec[i] & 0xff000000) >> 24,
				(test_vec[i] & 0x00ff0000) >> 16,
				(test_vec[i] & 0x0000ff00) >>  8,
				(test_vec[i] & 0x000000ff) >>  0
			);

			c++;
		} else if (c == 4) {
			MSG_OUT("\n");
			c = 0;
		}
	}
	MSG_OUT("\n");

	c = 0;

	// print generated output
	MSG_OUT("- produced output:\n");
        for (i = 0; i < SALSA_20_8_OUTPUT_WORDSIZE; i++) {
                if (c != 4) {
                        MSG_OUT("%02x %02x %02x %02x ",
                                (wbuf[i] & 0xff000000) >> 24,
                                (wbuf[i] & 0x00ff0000) >> 16,
                                (wbuf[i] & 0x0000ff00) >>  8,
                                (wbuf[i] & 0x000000ff) >>  0
                        );

                        c++;
                } else if (c == 4) {
                        MSG_OUT("\n");
                        c = 0;
                }
        }
        MSG_OUT("\n");
	MSG_OUT("-------------------------------------\n");

	static_cleanup(wbuf, SALSA_20_8_OUTPUT_WORDSIZE * sizeof(uint32_t));

	return 0;
}
