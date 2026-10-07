#ifndef GRID_EPOCH_SM3_H
#define GRID_EPOCH_SM3_H

#include <stddef.h>
#include <stdint.h>

void ge_sm3(const uint8_t *data, size_t len, uint8_t out[32]);
/* GB/T 32918.4 KDF：SM3(Z || ct)，ct 从 1 起，大端 32 位。zlen 不得超过 240。 */
int ge_sm3_kdf(const uint8_t *z, size_t zlen, uint8_t *out, size_t klen);

#endif
