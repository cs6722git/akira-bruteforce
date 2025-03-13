#include "chacha8.h"

#include <string.h>

__inline static unsigned int __attribute__((__always_inline__, __artificial__, __gnu_inline__)) _rotl(unsigned int value, int count)
{
    // count &= 31;
    return (value << count) | (value >> (-count & 31));
}


#define U32TO32_LITTLE(v) (v)
#define U8TO32_LITTLE(p) (*(const uint32_t *)(p))
#define U32TO8_LITTLE(p, v) (((uint32_t *)(p))[0] = U32TO32_LITTLE(v))
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define ROTATE(v, c) (ROTL32(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) ((v) + (w))
#define PLUSONE(v) (PLUS((v), 1))

//static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void chacha8_keysetup(struct chacha8_ctx *x, const uint8_t *k,  const uint8_t *iv)
{
    const char *constants;
    
    x->input[4] = U8TO32_LITTLE(k + 0);
    x->input[5] = U8TO32_LITTLE(k + 4);
    x->input[6] = U8TO32_LITTLE(k + 8);
    x->input[7] = U8TO32_LITTLE(k + 12);
    constants = tau;
    
    x->input[8] = U8TO32_LITTLE(k + 0);
    x->input[9] = U8TO32_LITTLE(k + 4);
    x->input[10] = U8TO32_LITTLE(k + 8);
    x->input[11] = U8TO32_LITTLE(k + 12);
    x->input[0] = U8TO32_LITTLE(constants + 0);
    x->input[1] = U8TO32_LITTLE(constants + 4);
    x->input[2] = U8TO32_LITTLE(constants + 8);
    x->input[3] = U8TO32_LITTLE(constants + 12);
    x->input[12] = 0;
    x->input[13] = 0;
    x->input[14] = U8TO32_LITTLE(iv + 0);
    x->input[15] = U8TO32_LITTLE(iv + 4);

}


typedef struct {
    uint32_t a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p;
} BLOCK;

#define QROUND(a, b, c, d)       \
    d = _rotl(d ^ (a += b), 16); \
    b = _rotl(b ^ (c += d), 12); \
    d = _rotl(d ^ (a += b), 8);  \
    b = _rotl(b ^ (c += d), 7)
#define FROUND                  \
    QROUND(x.d, x.h, x.l, x.p); \
    QROUND(x.c, x.g, x.k, x.o); \
    QROUND(x.b, x.f, x.j, x.n); \
    QROUND(x.a, x.e, x.i, x.m); \
    QROUND(x.a, x.f, x.k, x.p); \
    QROUND(x.b, x.g, x.l, x.m); \
    QROUND(x.c, x.h, x.i, x.n); \
    QROUND(x.d, x.e, x.j, x.o)
#define FFINAL  \
    x.a += j.a; \
    x.b += j.b; \
    x.c += j.c; \
    x.d += j.d; \
    x.e += j.e; \
    x.f += j.f; \
    x.g += j.g; \
    x.h += j.h; \
    x.i += j.i; \
    x.j += j.j; \
    x.k += j.k; \
    x.l += j.l; \
    x.m += j.m; \
    x.n += j.n; \
    x.o += j.o; \
    x.p += j.p

void chacha8_get_keystream(
    struct chacha8_ctx *ctx,
    uint64_t pos,
    uint32_t n_blocks,
    uint8_t *c)
{
    BLOCK x;
    BLOCK j;

    if (!n_blocks)
        return;

    memcpy(&j, ctx, sizeof(BLOCK));
    j.m = pos;
    j.n = pos >> 32;

_BLOCK_LOOP:

    memcpy(&x, &j, sizeof(BLOCK));

    FROUND;
    FROUND;
    FROUND;
    FROUND;
    FFINAL;

    memcpy(c, &x, sizeof(BLOCK));

    if (--n_blocks) {
        c += 64, j.n += !++j.m;
        goto _BLOCK_LOOP;
    }
}

void chacha8_xor_keystream(
     struct chacha8_ctx *ctx,
    uint64_t pos,
    uint32_t n_blocks,
    uint8_t *c)
{
    BLOCK x;
    BLOCK j;

    if (!n_blocks)
        return;

    memcpy(&j, ctx, sizeof(BLOCK));
    j.m = pos;
    j.n = pos >> 32;

_BLOCK_LOOP:

    memcpy(&x, &j, sizeof(BLOCK));

    FROUND;
    FROUND;
    FROUND;
    FROUND;
    FFINAL;

    uint8_t *src = (uint8_t *)&x;
    for (int i = 0; i < 64; i++) {
        c[i] ^= src[i];
    }

    if (--n_blocks) {
        c += 64, j.n += !++j.m;
        goto _BLOCK_LOOP;
    }
    //memcpy(ctx, &j, sizeof(BLOCK));
}


#define QUARTERROUND(a, b, c, d) \
    a = PLUS(a, b);              \
    d = ROTATE(XOR(d, a), 16);   \
    c = PLUS(c, d);              \
    b = ROTATE(XOR(b, c), 12);   \
    a = PLUS(a, b);              \
    d = ROTATE(XOR(d, a), 8);    \
    c = PLUS(c, d);              \
    b = ROTATE(XOR(b, c), 7)

void chacha8_get_keystream_oneblock(
    const struct chacha8_ctx *ctx,
    uint8_t *c)
{
    BLOCK x;
    BLOCK j;

    memcpy(&j, ctx, sizeof(BLOCK));
    j.m = 0;
    j.n = 0;

    memcpy(&x, &j, sizeof(BLOCK));

    FROUND;
    FROUND;
    FROUND;
    FROUND;
    FFINAL;

    memcpy(c, &x, sizeof(BLOCK));

}


