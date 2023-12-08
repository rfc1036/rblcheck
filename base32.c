/*
 * base32 encoder based on public domain code written by C.J.Wagenius.
 * https://github.com/cjwagenius/base32/
 *
 * base16 encoder written by Marco d'Itri.
 *
 * SPDX-License-Identifier: CC-PDDC
 */
#include <stdlib.h>
#include <string.h>

#include "base32.h"

#ifdef __GNUC__
# define fallthrough __attribute__((fallthrough))
#else
# define fallthrough do { } while (0)
#endif

static size_t base32_encode_group(char *dst, const void *src, size_t nb)
{
    static const char b32map[] = "abcdefghijklmnopqrstuvwxyz234567";
    unsigned short b32 = 0;
    const unsigned char *s = src;

    if (nb > 5)
	nb = 5;
    switch (nb) {
    case 5:
	b32 = (s[4] & 0x1f);
	dst[7] = b32map[b32];
	fallthrough;
    case 4:
	b32 = (s[3] & 0x03) << 3 | (s[4] & 0xe0) >> 5;
	dst[6] = b32map[b32];
	b32 = (s[3] & 0x7c) >> 2;
	dst[5] = b32map[b32];
	fallthrough;
    case 3:
	b32 = (s[2] & 0x0f) << 1 | (s[3] & 0x80) >> 7;
	dst[4] = b32map[b32];
	fallthrough;
    case 2:
	b32 = (s[1] & 0x01) << 4 | (s[2] & 0xf0) >> 4;
	dst[3] = b32map[b32];
	b32 = (s[1] & 0x3e) >> 1;
	dst[2] = b32map[b32];
	fallthrough;
    default:
	b32 = (s[0] & 0x07) << 2 | (s[1] & 0xc0) >> 6;
	dst[1] = b32map[b32];
	b32 = (s[0] & 0xf8) >> 3;
	dst[0] = b32map[b32];
    }

    return nb;
}

char *base32_encode(const void *src, size_t len)
{
    const char *p_src;
    char *dst, *p_dst;
    size_t dst_len;

    if (len == 0)
	len = strlen(src);
    /* compute the length of the encoded string */
    dst_len = len / 5;
    dst_len += len % 5 ? 1 : 0;
    dst_len *= 8;

    dst = malloc(dst_len + 1);
    if (!dst)
	return NULL;
    memset(dst, '\0', dst_len + 1);

    p_src = src;
    p_dst = dst;
    while (len) {
	len -= base32_encode_group(p_dst, p_src, len);
	p_src += 5;
	p_dst += 8;
    }

    return dst;
}

char *base16_encode(const void *src, size_t len)
{
    static const char b16map[] = "0123456789abcdef";
    char *dst;
    size_t dst_len, i;
    const unsigned char *s = src;

    if (len == 0)
	len = strlen(src);
    dst_len = len * 2;

    dst = malloc(dst_len + 1);
    if (!dst)
	return NULL;
    dst[dst_len] = '\0';

    for (i = 0; i < len; i++) {
	dst[i*2]     = b16map[s[i] >> 4];
	dst[i*2 + 1] = b16map[s[i] & 0x0F];
    }

    return dst;
}

#ifdef TEST
#include <stdio.h>

int main(void)
{
    const char *s = "\x01\x02\x03\x04\x05\x06\x07\x08\x00\x09\x0a\x0b\x0c";
    char *r;

    r = base32_encode(s, 13);
    if (!r)
	exit(-1);
    printf("%s\n", r);
    r = base16_encode(s, 13);
    if (!r)
	exit(-1);
    printf("%s\n", r);
    exit(0);
}
#endif

