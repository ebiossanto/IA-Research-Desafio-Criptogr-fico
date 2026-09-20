/**
 * CifraTeste-1024: Block cipher with 1024-bit block and 256-bit key
 *
 * SPN structure: SubBytes + ShiftRows + MixColumns(GF(2^8)) + AddRoundKey
 * Key schedule: Blake3-inspired CVB construction
 *
 * Security target: 256-bit classical security
 */

#ifndef CIFRATESTE1024_H
#define CIFRATESTE1024_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CT_NO_MAIN
/* default: no main */
#endif

#define CT_BLOCK_SIZE   128
#define CT_KEY_SIZE     32
#define CT_STATE_SIZE   128
#define CT_ROUNDS       16
#define CT_WORDS        16
#define CT_SBOX_SIZE    256

typedef struct {
    uint64_t round_keys[CT_ROUNDS][CT_WORDS];
} ct_subkeys_t;

void ct_keygen(const uint64_t master_key[4], ct_subkeys_t *subkeys);
void ct_encrypt(uint64_t state[16], const uint64_t master_key[4]);
void ct_decrypt(uint64_t state[16], const uint64_t master_key[4]);

size_t ct_encrypt_buffer(const uint8_t *input, size_t input_len,
                         const uint64_t master_key[4], uint8_t **output);
long long ct_decrypt_buffer(const uint8_t *input, size_t input_len,
                            const uint64_t master_key[4], uint8_t *output);

const uint8_t* ct_get_sbox(void);
const uint8_t* ct_get_inv_sbox(void);

#ifdef __cplusplus
}
#endif

#endif
