#include "batch.h"

#include "sm3.h"
#include "sm4.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void store_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void xor_bytes(uint8_t *acc, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        acc[i] ^= p[i];
    }
}

static int city_keys(const uint8_t mk_mgmt[32], const uint8_t mk_biz[32],
                     uint32_t area, uint32_t cohort,
                     uint8_t out_mgmt[32], uint8_t out_biz[32]) {
    uint8_t z[44];
    memcpy(z, mk_mgmt, 32);
    memcpy(z + 32, "CITY", 4);
    store_be32(z + 36, cohort);
    if (ge_sm3_kdf(z, 40, out_mgmt, 32) != 0) {
        return -1;
    }
    memcpy(z, mk_biz, 32);
    memcpy(z + 32, "CIBZ", 4);
    store_be32(z + 36, area);
    store_be32(z + 40, cohort);
    return ge_sm3_kdf(z, 44, out_biz, 32);
}

static int tagged_county(const uint8_t parent[32], const char tag[4], uint32_t county,
                          uint8_t out[32]) {
    uint8_t z[40];
    memcpy(z, parent, 32);
    memcpy(z + 32, tag, 4);
    store_be32(z + 36, county);
    return ge_sm3_kdf(z, 40, out, 32);
}

static int zone_from_county(const uint8_t county_mgmt[32], uint32_t area, uint32_t zone,
                            uint8_t out[32]) {
    uint8_t z[44];
    memcpy(z, county_mgmt, 32);
    memcpy(z + 32, "ZONE", 4);
    store_be32(z + 36, area);
    store_be32(z + 40, zone);
    return ge_sm3_kdf(z, 44, out, 32);
}

int ge_seed_pair(const uint8_t mk_mgmt[32], const uint8_t mk_biz[32],
                 uint32_t area, uint32_t cohort, uint32_t county, uint32_t zone,
                 uint64_t tid, uint8_t seed_mgmt[32], uint8_t seed_biz[32]) {
    uint8_t cm[32], cb[32], cnm[32], cnb[32], zk[32];
    uint8_t z[48];
    if (city_keys(mk_mgmt, mk_biz, area, cohort, cm, cb) != 0) {
        return -1;
    }
    if (tagged_county(cm, "CNTY", county, cnm) != 0 || tagged_county(cb, "CNBZ", county, cnb) != 0) {
        return -1;
    }
    if (zone_from_county(cnm, area, zone, zk) != 0) {
        return -1;
    }
    memcpy(z, zk, 32);
    memcpy(z + 32, "MGMT", 4);
    store_be64(z + 36, tid);
    if (ge_sm3_kdf(z, 44, seed_mgmt, 32) != 0) {
        return -1;
    }
    memcpy(z, cnb, 32);
    memcpy(z + 32, "BIZ0", 4);
    store_be32(z + 36, zone);
    store_be64(z + 40, tid);
    return ge_sm3_kdf(z, 48, seed_biz, 32);
}

int ge_auth_key(const uint8_t auth_leaf[32], uint32_t epoch,
                const uint8_t nonce[16], uint8_t out[16]) {
    uint8_t z[56];
    memcpy(z, auth_leaf, 32);
    memcpy(z + 32, "AUTH", 4);
    store_be32(z + 36, epoch);
    memcpy(z + 40, nonce, 16);
    return ge_sm3_kdf(z, 56, out, 16);
}

int ge_biz_key(const uint8_t seed_biz[32], uint32_t epoch,
               const uint8_t nonce[16], uint8_t out[16]) {
    uint8_t z[56];
    memcpy(z, seed_biz, 32);
    memcpy(z + 32, "BIZK", 4);
    store_be32(z + 36, epoch);
    memcpy(z + 40, nonce, 16);
    return ge_sm3_kdf(z, 56, out, 16);
}

static int walk_era(const uint8_t root[32], uint32_t epoch_in_era, uint8_t out[32]) {
    if (epoch_in_era < 1 || epoch_in_era > 65536u) {
        return -1;
    }
    uint32_t index = epoch_in_era - 1u;
    uint8_t node[32];
    memcpy(node, root, 32);
    for (int depth = 0; depth < 16; depth++) {
        int bit = (int)((index >> (15 - depth)) & 1u);
        uint8_t z[37];
        memcpy(z, node, 32);
        memcpy(z + 32, bit ? "FSR1" : "FSL0", 4);
        z[36] = (uint8_t)depth;
        if (ge_sm3_kdf(z, 37, node, 32) != 0) {
            return -1;
        }
    }
    memcpy(out, node, 32);
    return 0;
}

int ge_time_leaf(const uint8_t root[32], uint32_t epoch, uint8_t out[32]) {
    if (epoch < 1) {
        return -1;
    }
    uint32_t era = (epoch - 1u) / 65536u;
    uint32_t local = (epoch - 1u) % 65536u + 1u;
    uint8_t node[32];
    uint8_t last[32];
    memcpy(node, root, 32);
    for (uint32_t i = 0; i < era; i++) {
        uint8_t z[36];
        if (walk_era(node, 65536u, last) != 0) {
            return -1;
        }
        memcpy(z, last, 32);
        memcpy(z + 32, "NEXT", 4);
        if (ge_sm3_kdf(z, 36, node, 32) != 0) {
            return -1;
        }
    }
    return walk_era(node, local, out);
}

void ge_hmac_sm3(const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen, uint8_t out[32]) {
    uint8_t k[64];
    memset(k, 0, sizeof k);
    if (keylen > 64) {
        ge_sm3(key, keylen, k);
    } else if (keylen) {
        memcpy(k, key, keylen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    uint8_t stack[64 + 96];
    uint8_t *inner_in = stack;
    uint8_t *heap = NULL;
    if (msglen > 96) {
        heap = (uint8_t *)malloc(64 + msglen);
        inner_in = heap;
    }
    memcpy(inner_in, ipad, 64);
    if (msglen) {
        memcpy(inner_in + 64, msg, msglen);
    }
    uint8_t inner[32];
    ge_sm3(inner_in, 64 + msglen, inner);
    free(heap);
    uint8_t outer[96];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, inner, 32);
    ge_sm3(outer, 96, out);
}

int ge_aead_open(const uint8_t key[16], const uint8_t *sealed, size_t sealed_len,
                 uint8_t *plain, size_t plain_cap, size_t *plain_len) {
    if (sealed_len < 16 + 2 + 32) {
        return -1;
    }
    uint16_t ct_len = (uint16_t)((sealed[16] << 8) | sealed[17]);
    if ((size_t)16 + 2 + ct_len + 32 != sealed_len || ct_len > plain_cap || ct_len > 256) {
        return -1;
    }
    const uint8_t *iv = sealed;
    const uint8_t *ct = sealed + 18;
    const uint8_t *mac = ct + ct_len;
    uint8_t label[20];
    uint8_t enc[16];
    uint8_t mac_key[16];
    memcpy(label, key, 16);
    memcpy(label + 16, "AENC", 4);
    if (ge_sm3_kdf(label, 20, enc, 16) != 0) {
        return -1;
    }
    memcpy(label + 16, "AMAC", 4);
    if (ge_sm3_kdf(label, 20, mac_key, 16) != 0) {
        return -1;
    }
    uint8_t msg[1 + 16 + 256];
    msg[0] = 0x01;
    memcpy(msg + 1, iv, 16);
    if (ct_len) {
        memcpy(msg + 17, ct, ct_len);
    }
    uint8_t calc[32];
    ge_hmac_sm3(mac_key, 16, msg, (size_t)17 + ct_len, calc);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (uint8_t)(calc[i] ^ mac[i]);
    }
    if (diff) {
        return -2;
    }
    ge_sm4_ctr(enc, iv, ct, plain, ct_len);
    *plain_len = ct_len;
    return 0;
}

static uint64_t make_tid(uint32_t zone, uint32_t local) {
    return ((uint64_t)zone << 16) | (uint64_t)local;
}

typedef struct {
    const uint8_t *mk_mgmt;
    const uint8_t *mk_biz;
    uint32_t area;
    uint32_t cohort;
    uint32_t zone_begin;
    uint32_t per_zone;
    uint32_t zone_lo;
    uint32_t zone_hi;
    uint32_t county_width;
    uint8_t *mgmt;
    uint8_t *biz;
    uint8_t xor_mgmt[32];
    uint8_t xor_biz[32];
    int store;
    int rc;
} ProvWork;

static void *prov_worker(void *arg) {
    ProvWork *w = (ProvWork *)arg;
    memset(w->xor_mgmt, 0, 32);
    memset(w->xor_biz, 0, 32);
    w->rc = 0;
    uint8_t cm[32], cb[32];
    if (city_keys(w->mk_mgmt, w->mk_biz, w->area, w->cohort, cm, cb) != 0) {
        w->rc = -1;
        return NULL;
    }
    uint32_t cached = 0xffffffffu;
    uint8_t cnm[32], cnb[32];
    for (uint32_t zone = w->zone_lo; zone < w->zone_hi; zone++) {
        uint32_t county = zone / w->county_width;
        uint8_t zk[32];
        if (county != cached) {
            if (tagged_county(cm, "CNTY", county, cnm) != 0 || tagged_county(cb, "CNBZ", county, cnb) != 0) {
                w->rc = -1;
                return NULL;
            }
            cached = county;
        }
        if (zone_from_county(cnm, w->area, zone, zk) != 0) {
            w->rc = -1;
            return NULL;
        }
        for (uint32_t local = 0; local < w->per_zone; local++) {
            uint64_t tid = make_tid(zone, local);
            uint8_t sm[32], sb[32];
            uint8_t z[48];
            memcpy(z, zk, 32);
            memcpy(z + 32, "MGMT", 4);
            store_be64(z + 36, tid);
            if (ge_sm3_kdf(z, 44, sm, 32) != 0) {
                w->rc = -1;
                return NULL;
            }
            memcpy(z, cnb, 32);
            memcpy(z + 32, "BIZ0", 4);
            store_be32(z + 36, zone);
            store_be64(z + 40, tid);
            if (ge_sm3_kdf(z, 48, sb, 32) != 0) {
                w->rc = -1;
                return NULL;
            }
            xor_bytes(w->xor_mgmt, sm, 32);
            xor_bytes(w->xor_biz, sb, 32);
            if (w->store) {
                uint64_t index = ((uint64_t)(zone - w->zone_begin) * w->per_zone) + local;
                memcpy(w->mgmt + index * 32, sm, 32);
                memcpy(w->biz + index * 32, sb, 32);
            }
        }
    }
    return NULL;
}

static int run_provision(const uint8_t mk_mgmt[32], const uint8_t mk_biz[32],
                         uint32_t area, uint32_t cohort, uint32_t zone_begin,
                         uint32_t n_zones, uint32_t per_zone, uint32_t county_width,
                         int threads, int store,
                         uint8_t *mgmt, uint8_t *biz,
                         uint8_t xor_mgmt[32], uint8_t xor_biz[32]) {
    if (n_zones == 0 || per_zone == 0 || per_zone > 65535 || county_width == 0 || threads < 1) {
        return -1;
    }
    if (threads > (int)n_zones) {
        threads = (int)n_zones;
    }
    ProvWork *works = (ProvWork *)calloc((size_t)threads, sizeof(ProvWork));
    pthread_t *ths = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));
    if (!works || !ths) {
        free(works);
        free(ths);
        return -1;
    }
    uint32_t base = n_zones / (uint32_t)threads;
    uint32_t extra = n_zones % (uint32_t)threads;
    uint32_t cursor = zone_begin;
    for (int t = 0; t < threads; t++) {
        uint32_t take = base + ((uint32_t)t < extra ? 1u : 0u);
        works[t].mk_mgmt = mk_mgmt;
        works[t].mk_biz = mk_biz;
        works[t].area = area;
        works[t].cohort = cohort;
        works[t].zone_begin = zone_begin;
        works[t].per_zone = per_zone;
        works[t].zone_lo = cursor;
        works[t].zone_hi = cursor + take;
        works[t].county_width = county_width;
        works[t].mgmt = mgmt;
        works[t].biz = biz;
        works[t].store = store;
        cursor += take;
        if (pthread_create(&ths[t], NULL, prov_worker, &works[t]) != 0) {
            for (int j = 0; j < t; j++) {
                pthread_join(ths[j], NULL);
            }
            free(works);
            free(ths);
            return -1;
        }
    }
    int rc = 0;
    memset(xor_mgmt, 0, 32);
    memset(xor_biz, 0, 32);
    for (int t = 0; t < threads; t++) {
        pthread_join(ths[t], NULL);
        if (works[t].rc != 0) {
            rc = works[t].rc;
        }
        xor_bytes(xor_mgmt, works[t].xor_mgmt, 32);
        xor_bytes(xor_biz, works[t].xor_biz, 32);
    }
    free(works);
    free(ths);
    return rc;
}

int ge_stream_topology(const uint8_t mk_mgmt[32], const uint8_t mk_biz[32],
                       uint32_t area, uint32_t cohort, uint32_t zone_begin,
                       uint32_t n_zones, uint32_t per_zone, uint32_t county_width,
                       int threads, uint8_t xor_mgmt[32], uint8_t xor_biz[32]) {
    return run_provision(mk_mgmt, mk_biz, area, cohort, zone_begin, n_zones, per_zone,
                         county_width, threads, 0, NULL, NULL, xor_mgmt, xor_biz);
}

GESeedTable *ge_provision(const uint8_t mk_mgmt[32], const uint8_t mk_biz[32],
                          uint32_t area, uint32_t cohort, uint32_t zone_begin,
                          uint32_t n_zones, uint32_t per_zone, uint32_t county_width,
                          int threads) {
    uint64_t count = (uint64_t)n_zones * (uint64_t)per_zone;
    GESeedTable *table = (GESeedTable *)calloc(1, sizeof(GESeedTable));
    if (!table) {
        return NULL;
    }
    table->count = count;
    table->mgmt = (uint8_t *)malloc(count * 32);
    table->biz = (uint8_t *)malloc(count * 32);
    if (!table->mgmt || !table->biz) {
        ge_seed_table_free(table);
        return NULL;
    }
    uint8_t xm[32], xb[32];
    if (run_provision(mk_mgmt, mk_biz, area, cohort, zone_begin, n_zones, per_zone,
                      county_width, threads, 1, table->mgmt, table->biz, xm, xb) != 0) {
        ge_seed_table_free(table);
        return NULL;
    }
    return table;
}

void ge_seed_table_free(GESeedTable *table) {
    if (!table) {
        return;
    }
    free(table->mgmt);
    free(table->biz);
    free(table);
}

typedef struct {
    const GESeedTable *table;
    const uint8_t *root_key;
    const uint8_t *sealed;
    size_t sealed_len;
    uint64_t lo;
    uint64_t hi;
    uint8_t xor_auth[16];
    uint8_t xor_biz[16];
    int rc;
} UpdWork;

static void *upd_worker(void *arg) {
    UpdWork *w = (UpdWork *)arg;
    memset(w->xor_auth, 0, 16);
    memset(w->xor_biz, 0, 16);
    w->rc = 0;
    for (uint64_t i = w->lo; i < w->hi; i++) {
        uint8_t plain[64];
        size_t plen = 0;
        if (ge_aead_open(w->root_key, w->sealed, w->sealed_len, plain, sizeof plain, &plen) != 0 ||
            plen != 36) {
            w->rc = -2;
            return NULL;
        }
        uint32_t epoch = load_be32(plain);
        const uint8_t *auth_nonce = plain + 4;
        const uint8_t *biz_nonce = plain + 20;
        uint8_t auth[16], biz[16], leaf[32], auth_leaf[32];
        if (ge_time_leaf(w->table->biz + i * 32, epoch, leaf) != 0 ||
            ge_time_leaf(w->table->mgmt + i * 32, epoch, auth_leaf) != 0 ||
            ge_auth_key(auth_leaf, epoch, auth_nonce, auth) != 0 ||
            ge_biz_key(leaf, epoch, biz_nonce, biz) != 0) {
            w->rc = -1;
            return NULL;
        }
        xor_bytes(w->xor_auth, auth, 16);
        xor_bytes(w->xor_biz, biz, 16);
    }
    return NULL;
}

int ge_parallel_update(const GESeedTable *table, const uint8_t root_key[16],
                       const uint8_t *sealed, size_t sealed_len, int threads,
                       uint8_t xor_auth[16], uint8_t xor_biz[16]) {
    if (!table || table->count == 0 || threads < 1) {
        return -1;
    }
    if (threads > 256) {
        threads = 256;
    }
    if ((uint64_t)threads > table->count) {
        threads = (int)table->count;
    }
    UpdWork *works = (UpdWork *)calloc((size_t)threads, sizeof(UpdWork));
    pthread_t *ths = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));
    if (!works || !ths) {
        free(works);
        free(ths);
        return -1;
    }
    uint64_t base = table->count / (uint64_t)threads;
    uint64_t extra = table->count % (uint64_t)threads;
    uint64_t cursor = 0;
    for (int t = 0; t < threads; t++) {
        uint64_t take = base + ((uint64_t)t < extra ? 1u : 0u);
        works[t].table = table;
        works[t].root_key = root_key;
        works[t].sealed = sealed;
        works[t].sealed_len = sealed_len;
        works[t].lo = cursor;
        works[t].hi = cursor + take;
        cursor += take;
        if (pthread_create(&ths[t], NULL, upd_worker, &works[t]) != 0) {
            for (int j = 0; j < t; j++) {
                pthread_join(ths[j], NULL);
            }
            free(works);
            free(ths);
            return -1;
        }
    }
    int rc = 0;
    memset(xor_auth, 0, 16);
    memset(xor_biz, 0, 16);
    for (int t = 0; t < threads; t++) {
        pthread_join(ths[t], NULL);
        if (works[t].rc != 0) {
            rc = works[t].rc;
        }
        xor_bytes(xor_auth, works[t].xor_auth, 16);
        xor_bytes(xor_biz, works[t].xor_biz, 16);
    }
    free(works);
    free(ths);
    return rc;
}

int ge_ack_tag(const uint8_t seed_biz[32], uint32_t zone, uint64_t tid,
               uint32_t epoch, const uint8_t nonce[16], uint8_t out[16]) {
    uint8_t leaf[32];
    uint8_t key[16];
    uint8_t mac[32];
    uint8_t z[56];
    uint8_t msg[20];
    if (ge_time_leaf(seed_biz, epoch, leaf) != 0) {
        return -1;
    }
    memcpy(z, leaf, 32);
    memcpy(z + 32, "ACKK", 4);
    store_be32(z + 36, epoch);
    memcpy(z + 40, nonce, 16);
    if (ge_sm3_kdf(z, 56, key, 16) != 0) {
        return -1;
    }
    memcpy(msg, "ACK1", 4);
    store_be32(msg + 4, zone);
    store_be64(msg + 8, tid);
    store_be32(msg + 16, epoch);
    ge_hmac_sm3(key, 16, msg, 20, mac);
    memcpy(out, mac, 16);
    return 0;
}

typedef struct {
    const uint8_t *mk_biz;
    uint32_t area;
    uint32_t cohort;
    uint32_t zone_begin;
    uint32_t per_zone;
    uint32_t epoch;
    uint32_t county_width;
    const uint8_t *nonce;
    uint32_t zone_lo;
    uint32_t zone_hi;
    uint8_t xor_tag[16];
    int rc;
} AckWork;

static void *ack_worker(void *arg) {
    AckWork *w = (AckWork *)arg;
    memset(w->xor_tag, 0, 16);
    w->rc = 0;
    uint8_t cb[32];
    uint8_t label[44];
    memcpy(label, w->mk_biz, 32);
    memcpy(label + 32, "CIBZ", 4);
    store_be32(label + 36, w->area);
    store_be32(label + 40, w->cohort);
    if (ge_sm3_kdf(label, 44, cb, 32) != 0) {
        w->rc = -1;
        return NULL;
    }
    uint32_t cached = 0xffffffffu;
    uint8_t cnb[32];
    for (uint32_t zone = w->zone_lo; zone < w->zone_hi; zone++) {
        uint32_t county = zone / w->county_width;
        if (county != cached) {
            if (tagged_county(cb, "CNBZ", county, cnb) != 0) {
                w->rc = -1;
                return NULL;
            }
            cached = county;
        }
        for (uint32_t local = 0; local < w->per_zone; local++) {
            uint64_t tid = make_tid(zone, local);
            uint8_t seed[32];
            uint8_t z[48];
            uint8_t tag[16];
            memcpy(z, cnb, 32);
            memcpy(z + 32, "BIZ0", 4);
            store_be32(z + 36, zone);
            store_be64(z + 40, tid);
            if (ge_sm3_kdf(z, 48, seed, 32) != 0 ||
                ge_ack_tag(seed, zone, tid, w->epoch, w->nonce, tag) != 0) {
                w->rc = -1;
                return NULL;
            }
            xor_bytes(w->xor_tag, tag, 16);
        }
    }
    return NULL;
}

int ge_stream_ack(const uint8_t mk_biz[32], uint32_t area, uint32_t cohort,
                  uint32_t zone_begin, uint32_t n_zones, uint32_t per_zone,
                  uint32_t county_width, uint32_t epoch, const uint8_t nonce[16],
                  int threads, uint8_t xor_tag[16]) {
    if (n_zones == 0 || per_zone == 0 || per_zone > 65535 || county_width == 0 || threads < 1 || nonce == NULL) {
        return -1;
    }
    if (epoch < 1) {
        return -1;
    }
    if (threads > (int)n_zones) {
        threads = (int)n_zones;
    }
    if (threads > 256) {
        threads = 256;
    }
    AckWork *works = (AckWork *)calloc((size_t)threads, sizeof(AckWork));
    pthread_t *ths = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));
    if (!works || !ths) {
        free(works);
        free(ths);
        return -1;
    }
    uint32_t base = n_zones / (uint32_t)threads;
    uint32_t extra = n_zones % (uint32_t)threads;
    uint32_t cursor = zone_begin;
    for (int t = 0; t < threads; t++) {
        uint32_t take = base + ((uint32_t)t < extra ? 1u : 0u);
        works[t].mk_biz = mk_biz;
        works[t].area = area;
        works[t].cohort = cohort;
        works[t].zone_begin = zone_begin;
        works[t].per_zone = per_zone;
        works[t].epoch = epoch;
        works[t].county_width = county_width;
        works[t].nonce = nonce;
        works[t].zone_lo = cursor;
        works[t].zone_hi = cursor + take;
        cursor += take;
        if (pthread_create(&ths[t], NULL, ack_worker, &works[t]) != 0) {
            for (int j = 0; j < t; j++) {
                pthread_join(ths[j], NULL);
            }
            free(works);
            free(ths);
            return -1;
        }
    }
    int rc = 0;
    memset(xor_tag, 0, 16);
    for (int t = 0; t < threads; t++) {
        pthread_join(ths[t], NULL);
        if (works[t].rc != 0) {
            rc = works[t].rc;
        }
        xor_bytes(xor_tag, works[t].xor_tag, 16);
    }
    free(works);
    free(ths);
    return rc;
}

int ge_selftest(void) {
    static const uint8_t abc[3] = {'a', 'b', 'c'};
    static const uint8_t expect_abc[32] = {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
    };
    uint8_t out[32];
    ge_sm3(abc, 3, out);
    if (memcmp(out, expect_abc, 32) != 0) {
        return -1;
    }
    static const uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t pt[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t ct[16] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };
    ge_sm4_encrypt_block(key, pt, out);
    if (memcmp(out, ct, 16) != 0) {
        return -2;
    }
    return 0;
}
