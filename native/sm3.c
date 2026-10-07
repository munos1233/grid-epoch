#include "sm3.h"

#include <string.h>

static uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t p0(uint32_t x) {
    return x ^ rotl(x, 9) ^ rotl(x, 17);
}

static uint32_t p1(uint32_t x) {
    return x ^ rotl(x, 15) ^ rotl(x, 23);
}

static uint32_t ff(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

static uint32_t gg(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

static void compress(uint32_t v[8], const uint8_t block[64]) {
    uint32_t w[68];
    uint32_t w1[64];
    for (int j = 0; j < 16; j++) {
        w[j] = load_be32(block + 4 * j);
    }
    for (int j = 16; j < 68; j++) {
        uint32_t x = w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15);
        w[j] = p1(x) ^ rotl(w[j - 13], 7) ^ w[j - 6];
    }
    for (int j = 0; j < 64; j++) {
        w1[j] = w[j] ^ w[j + 4];
    }

    uint32_t a = v[0], b = v[1], c = v[2], d = v[3];
    uint32_t e = v[4], f = v[5], g = v[6], h = v[7];
    for (int j = 0; j < 64; j++) {
        uint32_t tj = (j < 16) ? 0x79cc4519u : 0x7a879d8au;
        uint32_t ss1 = rotl(rotl(a, 12) + e + rotl(tj, j & 31), 7);
        uint32_t ss2 = ss1 ^ rotl(a, 12);
        uint32_t tt1 = ff(a, b, c, j) + d + ss2 + w1[j];
        uint32_t tt2 = gg(e, f, g, j) + h + ss1 + w[j];
        d = c;
        c = rotl(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotl(f, 19);
        f = e;
        e = p0(tt2);
    }
    v[0] ^= a;
    v[1] ^= b;
    v[2] ^= c;
    v[3] ^= d;
    v[4] ^= e;
    v[5] ^= f;
    v[6] ^= g;
    v[7] ^= h;
}

void ge_sm3(const uint8_t *data, size_t len, uint8_t out[32]) {
    static const uint32_t iv[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };
    uint32_t v[8];
    memcpy(v, iv, sizeof v);

    size_t off = 0;
    while (len - off >= 64) {
        compress(v, data + off);
        off += 64;
    }

    uint8_t buf[128];
    memset(buf, 0, sizeof buf);
    size_t rem = len - off;
    if (rem) {
        memcpy(buf, data + off, rem);
    }
    buf[rem] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    if (rem <= 55) {
        for (int i = 0; i < 8; i++) {
            buf[63 - i] = (uint8_t)(bits >> (8 * i));
        }
        compress(v, buf);
    } else {
        compress(v, buf);
        memset(buf, 0, 64);
        for (int i = 0; i < 8; i++) {
            buf[63 - i] = (uint8_t)(bits >> (8 * i));
        }
        compress(v, buf);
    }

    for (int i = 0; i < 8; i++) {
        store_be32(out + 4 * i, v[i]);
    }
}

int ge_sm3_kdf(const uint8_t *z, size_t zlen, uint8_t *out, size_t klen) {
    if (zlen > 240 || (klen > 0 && out == NULL)) {
        return -1;
    }
    uint8_t buf[244];
    if (zlen) {
        memcpy(buf, z, zlen);
    }
    size_t done = 0;
    uint32_t ct = 1;
    while (done < klen) {
        store_be32(buf + zlen, ct);
        uint8_t hash[32];
        ge_sm3(buf, zlen + 4, hash);
        size_t n = klen - done;
        if (n > 32) {
            n = 32;
        }
        memcpy(out + done, hash, n);
        done += n;
        ct++;
    }
    return 0;
}
