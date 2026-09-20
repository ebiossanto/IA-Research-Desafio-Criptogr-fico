/**
 * CifraTeste-1024: SPN cipher with 1024-bit block, 256-bit key
 * Non-linearity: AES S-box (8-bit)
 * Diffusion: GF(2^8) MixColumns (4x4 AES MDS, applied 32 times)
 * Key schedule: Blake3-inspired CVB
 *
 * State layout: 128 bytes = 32 columns of 4 bytes.
 *   Byte at position col*4 + row, col=0..31, row=0..3.
 *   Column c contains bytes c*4, c*4+1, c*4+2, c*4+3.
 *   Row r is the set of bytes {c*4+r : c=0..31} (32 bytes).
 */
#include "cifrateste1024.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t CT_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};
static const uint8_t CT_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};
static const uint64_t CT_RC[CT_ROUNDS][2] = {
    {0x243f6a8885a308d3ULL, 0x13198a2e03707344ULL},
    {0xa4093822299f31d0ULL, 0x082efa98ec4e6c89ULL},
    {0x452821e638d01377ULL, 0xbe5466cf34e90c6cULL},
    {0xcac70c47b2c20958ULL, 0x818c0c0b5c268847ULL},
    {0xadd6a2d48de515aaULL, 0x09b6b8d3a7fd6196ULL},
    {0x5fa5b1e3d5a6e5c4ULL, 0x72b8e64a3cf1e8f3ULL},
    {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL},
    {0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL},
    {0x3956c25bf148e141ULL, 0x59f111f11b6028c1ULL},
    {0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL},
    {0xd807aa98a3030242ULL, 0x12835b0145706fbeULL},
    {0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL},
    {0x650a73548baf63deULL, 0x766d016c1c737a12ULL},
    {0x8111a63f4a6e3e3eULL, 0xf3d9b5c2a26c6d2bULL},
    {0x9c2e4a17f8b5c6d1ULL, 0x2e5d8c3a91b4f076ULL},
    {0xc4a72e5d8f3b1a60ULL, 0x19d2e4c7b8a5f301ULL},
};

const uint8_t* ct_get_sbox(void) { return CT_SBOX; }
const uint8_t* ct_get_inv_sbox(void) { return CT_INV_SBOX; }

/* GF(2^8) multiply with irreducible polynomial 0x11B */
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/* Rotate left for bytes within a 64-bit word (for key schedule) */
static uint64_t rotl_bytes(uint64_t x, int shift) {
    shift &= 7;
    if (shift == 0) return x;
    uint8_t bytes[8];
    memcpy(bytes, &x, 8);
    uint8_t tmp[8];
    for (int i = 0; i < 8; i++)
        tmp[i] = bytes[(i + shift) & 7];
    uint64_t result;
    memcpy(&result, tmp, 8);
    return result;
}

static uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

/* Blake3-inspired CVB compression */
static void cvb_compress(uint64_t *out, const uint64_t *L, const uint64_t *R,
                         uint64_t rc0, uint64_t rc1) {
    uint64_t v[4];
    v[0] = L[0] ^ R[0] ^ rc0;
    v[1] = L[1] ^ R[1] ^ rc1;
    v[2] = L[0] ^ R[1];
    v[3] = L[1] ^ R[0];
    v[0] += v[1]; v[1] = rotr64(v[1], 24); v[1] ^= v[0];
    v[2] += v[3]; v[3] = rotr64(v[3], 16); v[3] ^= v[2];
    v[0] += v[3]; v[3] = rotr64(v[3], 63); v[3] ^= v[0];
    v[1] += v[2]; v[2] = rotr64(v[2], 32); v[2] ^= v[1];
    v[0] += v[1]; v[1] = rotr64(v[1], 24); v[1] ^= v[0];
    v[2] += v[3]; v[3] = rotr64(v[3], 16); v[3] ^= v[2];
    v[0] += v[3]; v[3] = rotr64(v[3], 63); v[3] ^= v[0];
    v[1] += v[2]; v[2] = rotr64(v[2], 32); v[2] ^= v[1];
    out[0] = v[0] ^ v[2];
    out[1] = v[1] ^ v[3];
}

/* Key schedule */
void ct_keygen(const uint64_t master_key[4], ct_subkeys_t *subkeys) {
    uint64_t L[2] = {master_key[0], master_key[1]};
    uint64_t R[2] = {master_key[2], master_key[3]};
    for (int r = 0; r < CT_ROUNDS; r++) {
        uint64_t rk[2];
        cvb_compress(rk, L, R, CT_RC[r][0], CT_RC[r][1]);
        uint64_t chain[2] = {rk[0], rk[1]};
        for (int i = 0; i < CT_WORDS; i += 2) {
            uint64_t next[2];
            cvb_compress(next, chain, R, CT_RC[r][0] + i, CT_RC[r][1] + i);
            subkeys->round_keys[r][i] = next[0];
            subkeys->round_keys[r][i + 1] = next[1];
            chain[0] = next[0];
            chain[1] = next[1];
        }
        L[0] ^= rk[0]; L[1] ^= rk[1];
        uint64_t tmp = L[0]; L[0] = L[1]; L[1] = tmp;
        R[0] ^= L[0]; R[1] ^= L[1];
    }
}

/* ========================================================================= */
/*                        ROUND FUNCTIONS                                    */
/* ========================================================================= */

static void sub_bytes(uint8_t state[128]) {
    for (int i = 0; i < 128; i++)
        state[i] = CT_SBOX[state[i]];
}

static void inv_sub_bytes(uint8_t state[128]) {
    for (int i = 0; i < 128; i++)
        state[i] = CT_INV_SBOX[state[i]];
}

/*
 * ShiftRows: 32-byte rows, row r rotated LEFT by r positions.
 * State layout: byte at col*4 + row (col=0..31, row=0..3).
 * For each (col, row): byte moves from col*4+row to ((col+row)%32)*4+row.
 */
static void shift_rows(uint8_t state[128]) {
    uint8_t tmp[128];
    for (int col = 0; col < 32; col++) {
        for (int row = 0; row < 4; row++) {
            int dst = ((col + row) % 32) * 4 + row;
            tmp[dst] = state[col * 4 + row];
        }
    }
    memcpy(state, tmp, 128);
}

/*
 * InvShiftRows: 32-byte rows, row r rotated RIGHT by r positions.
 * For each (col, row): byte moves from col*4+row to ((col-row+32)%32)*4+row.
 */
static void inv_shift_rows(uint8_t state[128]) {
    uint8_t tmp[128];
    for (int col = 0; col < 32; col++) {
        for (int row = 0; row < 4; row++) {
            int dst = ((col - row + 32) % 32) * 4 + row;
            tmp[dst] = state[col * 4 + row];
        }
    }
    memcpy(state, tmp, 128);
}

/*
 * MixColumns: 4x4 AES MDS on each of 32 columns.
 * Each column c contains bytes state[c*4..c*4+3].
 * Circulant matrix with first row [2,3,1,1].
 */
static void mix_columns(uint8_t state[128]) {
    for (int c = 0; c < 32; c++) {
        int b = c * 4;
        uint8_t s0 = state[b];
        uint8_t s1 = state[b + 1];
        uint8_t s2 = state[b + 2];
        uint8_t s3 = state[b + 3];
        state[b]     = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3;
        state[b + 1] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
        state[b + 2] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
        state[b + 3] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2);
    }
}

/*
 * InvMixColumns: inverse of the 4x4 AES MDS on each of 32 columns.
 * Circulant matrix with first row [14,11,13,9].
 */
static void inv_mix_columns(uint8_t state[128]) {
    for (int c = 0; c < 32; c++) {
        int b = c * 4;
        uint8_t s0 = state[b];
        uint8_t s1 = state[b + 1];
        uint8_t s2 = state[b + 2];
        uint8_t s3 = state[b + 3];
        state[b]     = gf_mul(s0, 14) ^ gf_mul(s1, 11) ^ gf_mul(s2, 13) ^ gf_mul(s3, 9);
        state[b + 1] = gf_mul(s0, 9)  ^ gf_mul(s1, 14) ^ gf_mul(s2, 11) ^ gf_mul(s3, 13);
        state[b + 2] = gf_mul(s0, 13) ^ gf_mul(s1, 9)  ^ gf_mul(s2, 14) ^ gf_mul(s3, 11);
        state[b + 3] = gf_mul(s0, 11) ^ gf_mul(s1, 13) ^ gf_mul(s2, 9)  ^ gf_mul(s3, 14);
    }
}

static void add_round_key(uint8_t state[128], const uint64_t round_key[16]) {
    for (int i = 0; i < 16; i++) {
        uint64_t rk = round_key[i];
        uint8_t *s = state + i * 8;
        s[0] ^= (uint8_t)(rk);
        s[1] ^= (uint8_t)(rk >> 8);
        s[2] ^= (uint8_t)(rk >> 16);
        s[3] ^= (uint8_t)(rk >> 24);
        s[4] ^= (uint8_t)(rk >> 32);
        s[5] ^= (uint8_t)(rk >> 40);
        s[6] ^= (uint8_t)(rk >> 48);
        s[7] ^= (uint8_t)(rk >> 56);
    }
}

/* ========================================================================= */
/*                        ENCRYPT / DECRYPT                                  */
/* ========================================================================= */

/*
 * Encrypt: 15 rounds total (14 full + 1 final without MixColumns).
 * Round keys used: 0, 1, 2, ..., 15 (each exactly once).
 *
 * 1. AddRoundKey(0)
 * 2. Rounds 1..14: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey(r)
 * 3. Final round:  SubBytes -> ShiftRows -> AddRoundKey(15)
 */
void ct_encrypt(uint64_t state[16], const uint64_t master_key[4]) {
    ct_subkeys_t subkeys;
    ct_keygen(master_key, &subkeys);
    uint8_t *s = (uint8_t *)state;

    add_round_key(s, subkeys.round_keys[0]);

    for (int r = 1; r < CT_ROUNDS - 1; r++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, subkeys.round_keys[r]);
    }

    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, subkeys.round_keys[CT_ROUNDS - 1]);
}

/*
 * Decrypt: reverse of encrypt.
 *
 * 1. AddRoundKey(15) -> InvShiftRows -> InvSubBytes
 * 2. Rounds 14..1: AddRoundKey(r) -> InvMixColumns -> InvShiftRows -> InvSubBytes
 * 3. AddRoundKey(0)
 */
void ct_decrypt(uint64_t state[16], const uint64_t master_key[4]) {
    ct_subkeys_t subkeys;
    ct_keygen(master_key, &subkeys);
    uint8_t *s = (uint8_t *)state;

    add_round_key(s, subkeys.round_keys[CT_ROUNDS - 1]);
    inv_shift_rows(s);
    inv_sub_bytes(s);

    for (int r = CT_ROUNDS - 2; r >= 1; r--) {
        add_round_key(s, subkeys.round_keys[r]);
        inv_mix_columns(s);
        inv_shift_rows(s);
        inv_sub_bytes(s);
    }

    add_round_key(s, subkeys.round_keys[0]);
}

/* ========================================================================= */
/*                        BUFFER FUNCTIONS                                   */
/* ========================================================================= */

size_t ct_encrypt_buffer(const uint8_t *input, size_t input_len,
                         const uint64_t master_key[4], uint8_t **output) {
    size_t pad_len = CT_BLOCK_SIZE - (input_len % CT_BLOCK_SIZE);
    size_t ct_len = input_len + pad_len;
    *output = (uint8_t *)malloc(ct_len);
    if (!*output) return 0;
    memcpy(*output, input, input_len);
    for (size_t i = input_len; i < ct_len; i++)
        (*output)[i] = (uint8_t)pad_len;
    for (size_t off = 0; off < ct_len; off += CT_BLOCK_SIZE)
        ct_encrypt((uint64_t *)((*output) + off), master_key);
    return ct_len;
}

long long ct_decrypt_buffer(const uint8_t *input, size_t input_len,
                            const uint64_t master_key[4], uint8_t *output) {
    if (input_len % CT_BLOCK_SIZE != 0 || input_len == 0) return -1;
    memcpy(output, input, input_len);
    for (size_t off = 0; off < input_len; off += CT_BLOCK_SIZE)
        ct_decrypt((uint64_t *)(output + off), master_key);
    uint8_t pad = output[input_len - 1];
    if (pad == 0 || pad > CT_BLOCK_SIZE) return -1;
    for (size_t i = input_len - pad; i < input_len; i++)
        if (output[i] != pad) return -1;
    return (long long)(input_len - pad);
}
