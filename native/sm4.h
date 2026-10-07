#ifndef GRID_EPOCH_SM4_H
#define GRID_EPOCH_SM4_H

#include <stddef.h>
#include <stdint.h>

void ge_sm4_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void ge_sm4_ctr(const uint8_t key[16], const uint8_t iv[16],
                const uint8_t *in, uint8_t *out, size_t len);

#endif
