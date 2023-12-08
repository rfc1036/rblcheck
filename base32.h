#ifndef BASE32_H
#define BASE32_H

#include <stddef.h>

extern char *base32_encode(const void *, size_t);
extern char *base16_encode(const void *, size_t);

#endif
