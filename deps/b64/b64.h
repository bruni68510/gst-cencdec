
/**
 * `b64.h' - b64
 *
 * copyright (c) 2014 joseph werle
 */

#ifndef B64_H
#define B64_H 1

#include <stddef.h>

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);



#endif
