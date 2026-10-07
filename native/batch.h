#ifndef GRID_EPOCH_BATCH_H
#define GRID_EPOCH_BATCH_H

#include <stddef.h>
#include <stdint.h>

int ge_selftest(void);

void ge_hmac_sm3(const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen, uint8_t out[32]);

/* 与 Python derive.py 同一字节布局。种子经过县，再进台区和终端。 */
int ge_seed_pair(const uint8_t mk_mgmt[32], const uint8_t mk_biz[32],
                 uint32_t area, uint32_t cohort, uint32_t county, uint32_t zone,
                 uint64_t tid, uint8_t seed_mgmt[32], uint8_t seed_biz[32]);

/* 输入是认证时间树叶子，不是长期管控种子。 */
int ge_auth_key(const uint8_t auth_leaf[32], uint32_t epoch,
                const uint8_t nonce[16], uint8_t out[16]);
int ge_biz_key(const uint8_t leaf[32], uint32_t epoch,
               const uint8_t nonce[16], uint8_t out[16]);
/* 业务种子时间树叶子。65536 纪元换一代，下一代根是 KDF(末叶子 ‖ "NEXT")。 */
int ge_time_leaf(const uint8_t root[32], uint32_t epoch, uint8_t out[32]);

/*
 * 打开 AEAD：iv(16) || ct_len(2) || ct || mac(32)
 * enc = KDF(key ‖ "AENC")，mac_key = KDF(key ‖ "AMAC")
 * mac = HMAC-SM3(mac_key, 0x01 || iv || ct)
 */
int ge_aead_open(const uint8_t key[16], const uint8_t *sealed, size_t sealed_len,
                 uint8_t *plain, size_t plain_cap, size_t *plain_len);

typedef struct GESeedTable {
    uint8_t *mgmt;
    uint8_t *biz;
    uint64_t count;
} GESeedTable;

/* 流式派生，不保存密钥。xor_* 为全部种子的按字节异或，防止计算被裁掉。 */
int ge_stream_topology(const uint8_t mk_mgmt[32], const uint8_t mk_biz[32],
                       uint32_t area, uint32_t cohort, uint32_t zone_begin,
                       uint32_t n_zones, uint32_t per_zone, uint32_t county_width,
                       int threads, uint8_t xor_mgmt[32], uint8_t xor_biz[32]);

GESeedTable *ge_provision(const uint8_t mk_mgmt[32], const uint8_t mk_biz[32],
                          uint32_t area, uint32_t cohort, uint32_t zone_begin,
                          uint32_t n_zones, uint32_t per_zone, uint32_t county_width,
                          int threads);
void ge_seed_table_free(GESeedTable *table);

/*
 * 每个终端：打开同一条纪元密文，再派生认证密钥和业务密钥。
 * 路径密钥按代数长期有效，这一步不再滚动。SM2 验签由调用方单独计时。
 */
int ge_parallel_update(const GESeedTable *table, const uint8_t root_key[16],
                       const uint8_t *sealed, size_t sealed_len, int threads,
                       uint8_t xor_auth[16], uint8_t xor_biz[16]);

/* 业务叶子上的 16 字节完成标签。与 Python derive.completion_tag 同一布局。 */
int ge_ack_tag(const uint8_t seed_biz[32], uint32_t zone, uint64_t tid,
               uint32_t epoch, const uint8_t nonce[16], uint8_t out[16]);

/* 流式重算确认标签并异或，不保存标签。 */
int ge_stream_ack(const uint8_t mk_biz[32], uint32_t area, uint32_t cohort,
                  uint32_t zone_begin, uint32_t n_zones, uint32_t per_zone,
                  uint32_t county_width, uint32_t epoch, const uint8_t nonce[16],
                  int threads, uint8_t xor_tag[16]);

#endif
