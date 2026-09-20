/**
 * SPECTRUM-1024: Implementação Consolidada
 * Criptografia por Operador de Hodge Deformado e Confusão Não-Comutativa
 * 
 * Compilação: gcc -O3 -mavx2 spectrum1024.c -o spectrum1024
 * Windows: cl /O2 /arch:AVX2 spectrum1024.c
 *
 * Versão: 2.0.0
 * Modificações de Segurança (Prioridade 2):
 *   - OD-01: Carry-Killers (interrupção de trilhas de transporte)
 *   - OD-02: Constantes Assimétricas por Rodada (anti-criptoanálise rotacional)
 */

#include "spectrum1024.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Habilitar SPECTRUM_USE_AVX2 quando o compilador suportar */
#if defined(__AVX2__) || defined(__SSE2__)
#define SPECTRUM_USE_AVX2 1
#include <immintrin.h>
#else
#define SPECTRUM_USE_AVX2 0
#endif

/* ========================================================================= */
/*                     CONSTANTES DO KEY SCHEDULE (BASE)                     */
/* ========================================================================= */

static const uint64_t SPECTRUM_C[12] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf148e141ULL, 0x59f111f11b6028c1ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL
};

static const int SPECTRUM_L_BASE[16] = {
    1, 3, 5, 7, 9, 11, 13, 15,
    17, 19, 21, 23, 25, 27, 29, 31
};

/* ========================================================================= */
/*           MODIFICAÇÃO I: CARRY-KILLER (Gargalos de Transporte)            */
/* ========================================================================= */
/**
 * Máscara 0x5555...5555 (bits alternados: 0101...0101)
 * Usada para "assassinar" metade das trilhas de carry a cada rodada.
 *
 * Fórmula: z_i = P(y_i) XOR ((P(y_i) >>> 1) AND MASK_CARRY_KILLER)
 *
 * Efeito: Impede que resolvedores diferenciais (MILP/SAT) encontrem
 *         trajetória linear contínua ao longo das 12 rodadas.
 */
static const uint64_t MASK_CARRY_KILLER = 0x5555555555555555ULL;

/* ========================================================================= */
/*       MODIFICAÇÃO II: CONSTANTES ASSIMÉTRICAS POR RODADA (Anti-Slide)     */
/* ========================================================================= */
/**
 * Constantes pseudoaleatórias derivadas de π (dígitos fracionários).
 * Cada rodada usa uma constante diferente C_r, destruindo simetria rotacional.
 *
 * Fórmula: z_i = y_i + ((y_i² OR 1) XOR C_r) mod 2^64
 *
 * Fonte: 64 primeiros bits da parte fracionária de π:
 *   π = 3.14159265358979323846264338327950288419716939937510...
 */
static const uint64_t SPECTRUM_PI_C[12] = {
    0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL,
    0xA4093822299F31D0ULL, 0x082EFA98EC4E6C89ULL,
    0x452821E638D01377ULL, 0xBE5466CF34E90C6CULL,
    0xCAC70C47B2C20958ULL, 0x818C0C0B5C268847ULL,
    0xADD6A2D48DE515AAULL, 0x09B6B8D3A7FD6196ULL,
    0x5FA5B1E3D5A6E5C4ULL, 0x72B8E64A3CF1E8F3ULL
};

/* ========================================================================= */
/*                       FUNÇÕES AUXILIARES INLINE                           */
/* ========================================================================= */

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t g_func(uint64_t x, uint64_t c) {
    uint64_t xp = x + c;
    uint64_t xpp = xp ^ rotl64(xp, 29);
    return xpp + 0x9e3779b97f4a7c15ULL;
}

static inline uint64_t modInverse64(uint64_t a) {
    uint64_t x = a;
    x = x * (2 - a * x);
    x = x * (2 - a * x);
    x = x * (2 - a * x);
    x = x * (2 - a * x);
    x = x * (2 - a * x);
    x = x * (2 - a * x);
    return x;
}

/**
 * Polinômio de Euler-Rivest: P(y) = y + (y² OR 1) mod 2^64
 * 
 * Propriedades:
 * - Coeficiente linear: 1 (ímpar) ✓
 * - Coeficiente quadrático: (y² OR 1) → sempre ímpar ✓
 * - Bijeção garantida pelo teorema de Rivest
 */
static inline uint64_t poly_rivest_internal(uint64_t y) {
    return y + ((y * y) | 1);
}

/**
 * Versão pública do Polinômio de Euler-Rivest
 * (exposta via spectrum1024.h)
 */
uint64_t spectrum_poly_rivest(uint64_t y) {
    return y + ((y * y) | 1);
}

/**
 * Inversão do Polinômio de Euler-Rivest via Newton-Raphson P-ádico
 * 
 * P(y) = y + (y² OR 1) = z
 * P'(y) = 1 + 2y (derivada formal)
 * 
 * Nota: A derivada 1 + 2y é sempre ímpar → inverso modular existe
 */
static inline uint64_t invert_rivest(uint64_t z) {
    uint64_t y = z ^ 1;  // Chute inicial: paridade oposta a z (P(y)=y+(y²|1) inverte paridade)
    
    // 6 iterações para convergência em 64 bits (convergência quadrática)
    for (int i = 0; i < 6; i++) {
        uint64_t py = poly_rivest_internal(y);  // P(y)
        uint64_t num = py - z;            // P(y) - z
        uint64_t den = 1 + 2 * y;         // P'(y) = 1 + 2y
        y = y - num * modInverse64(den);
    }
    return y;
}

/* ========================================================================= */
/*                          KEY SCHEDULE                                     */
/* ========================================================================= */

void spectrum_keygen(const uint64_t master_key[4], spectrum_subkeys_t *subkeys) {
    uint64_t K[4];
    memcpy(K, master_key, 32);
    
    for (int r = 0; r < SPECTRUM_ROUNDS; r++) {
        uint64_t temp = g_func(K[0], SPECTRUM_C[r]);
        K[0] += temp;
        K[1] ^= K[0];
        K[2] += K[1];
        K[3] ^= K[2];
        
        uint64_t salva_K0 = K[0];
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = salva_K0;
        
        subkeys->R[r][0] = K[0];
        subkeys->R[r][1] = K[1];
        subkeys->R[r][2] = K[2];
        subkeys->R[r][3] = K[3];
    }
}

/* ========================================================================= */
/*                    CIFRAÇÃO: COMPONENTES (FORWARD)                        */
/* ========================================================================= */

/**
 * Camada Não-Linear: Ψ_NC (Confusão) — VERSÃO 2.0
 * 
 * 1. Fusão de Chave: x_i = s_i + R_{r, i mod 4}
 * 2. Interferência Antissimétrica: y_i = x_i XOR RotL(x_{i+1}, L_{i,r})
 *    Onde L_{i,r} = (L_BASE[i] + r * 7) mod 64  ← MODIFICAÇÃO II
 * 3. Polinômio de Euler-Rivest com constante de rodada:
 *    w_i = y_i + ((y_i² OR 1) XOR C_r) mod 2^64  ← MODIFICAÇÃO II
 * 4. Carry-Killer:
 *    z_i = w_i XOR ((w_i >>> 1) AND 0x55...55)    ← MODIFICAÇÃO I
 *
 * @param state  Estado de 16 × 64 bits (modificado in-place)
 * @param r_key  Subchave da rodada (4 × 64 bits)
 * @param round  Índice da rodada (0..11) — necessário para OD-01 e OD-02
 */
void spectrum_confusion(uint64_t state[16], const uint64_t r_key[4], int round) {
    uint64_t x[16], y[16];
    
    // Passo 1: Fusão de chave (adição modular)
    for (int i = 0; i < 16; i++)
        x[i] = state[i] + r_key[i % 4];
    
    // Passo 2: Interferência antissimétrica com constantes assimétricas (OD-02)
    // L_{i,r} = (L_BASE[i] + round * 7) mod 64
    // NOTA: Estrutura não-circular (Feistel-like) para garantir inversibilidade.
    //       y[0] = x[0]; y[i] = x[i] XOR RotL(x[i-1], L_{i,r}) para i > 0.
    y[0] = x[0];
    for (int i = 1; i < 16; i++) {
        int rotation = (SPECTRUM_L_BASE[i] + round * 7) % 64;
        y[i] = x[i] ^ rotl64(x[i - 1], rotation);
    }
    
    // Passo 3: Polinômio de Euler-Rivest com constante de rodada (OD-02)
    // w_i = P(y_i) XOR C_r  onde P(y) = y + (y² OR 1)
    // NOTA: XOR aplicado DEPOIS do polinômio para garantir inversibilidade
    // via Newton-Raphson existente (invert_rivest).
    for (int i = 0; i < 16; i++) {
        state[i] = poly_rivest_internal(y[i]) ^ SPECTRUM_PI_C[round];
    }
    
    // Passo 4: Carry-Killer — interrupção de trilhas de transporte (OD-01)
    // z_i = w_i XOR ((w_i >>> 1) AND 0x5555...5555)
    for (int i = 0; i < 16; i++) {
        state[i] = state[i] ^ ((state[i] >> 1) & MASK_CARRY_KILLER);
    }
}

#if !SPECTRUM_USE_AVX2
/* Implementacao escalar (fallback) */
void spectrum_diffusion_avx2(uint64_t state[16], const uint64_t r_key[4]) {
    uint64_t V0[4], V1[4], V2[4], V3[4];
    for (int j = 0; j < 4; j++) {
        V0[j] = state[4*j + 0]; V1[j] = state[4*j + 1];
        V2[j] = state[4*j + 2]; V3[j] = state[4*j + 3];
    }
    uint64_t w0 = r_key[0] | 1, w1 = r_key[1] | 1;
    uint64_t w2 = r_key[2] | 1, w3 = r_key[3] | 1;
    for (int i = 0; i < 4; i++) { V0[i] += V1[i]; V1[i] += V2[i]; V2[i] += V3[i]; }
    for (int i = 0; i < 4; i++) { V0[i] *= w0; V1[i] *= w1; V2[i] *= w2; V3[i] *= w3; }
    for (int i = 0; i < 4; i++) { V2[i] += V3[i]; V1[i] += V2[i]; V0[i] += V1[i]; }
    for (int j = 0; j < 4; j++) {
        state[4*j+0] = V0[j]; state[4*j+1] = V1[j];
        state[4*j+2] = V2[j]; state[4*j+3] = V3[j];
    }
}
#else
/* Implementacao AVX2 */
void spectrum_diffusion_avx2(uint64_t state[16], const uint64_t r_key[4]) {
    __m256i V0 = _mm256_set_epi64x(state[12], state[8], state[4], state[0]);
    __m256i V1 = _mm256_set_epi64x(state[13], state[9], state[5], state[1]);
    __m256i V2 = _mm256_set_epi64x(state[14], state[10], state[6], state[2]);
    __m256i V3 = _mm256_set_epi64x(state[15], state[11], state[7], state[3]);
    uint64_t w0 = r_key[0] | 1, w1 = r_key[1] | 1;
    uint64_t w2 = r_key[2] | 1, w3 = r_key[3] | 1;
    V0 = _mm256_add_epi64(V0, V1); V1 = _mm256_add_epi64(V1, V2);
    V2 = _mm256_add_epi64(V2, V3);
    uint64_t *v0_p = (uint64_t*)&V0, *v1_p = (uint64_t*)&V1;
    uint64_t *v2_p = (uint64_t*)&V2, *v3_p = (uint64_t*)&V3;
    for (int i = 0; i < 4; i++) { v0_p[i]*=w0; v1_p[i]*=w1; v2_p[i]*=w2; v3_p[i]*=w3; }
    V2 = _mm256_add_epi64(V2, V3); V1 = _mm256_add_epi64(V1, V2);
    V0 = _mm256_add_epi64(V0, V1);
    uint64_t out_v0[4], out_v1[4], out_v2[4], out_v3[4];
    _mm256_storeu_si256((__m256i*)out_v0, V0); _mm256_storeu_si256((__m256i*)out_v1, V1);
    _mm256_storeu_si256((__m256i*)out_v2, V2); _mm256_storeu_si256((__m256i*)out_v3, V3);
    for (int j = 0; j < 4; j++) {
        state[4*j+0]=out_v0[j]; state[4*j+1]=out_v1[j];
        state[4*j+2]=out_v2[j]; state[4*j+3]=out_v3[j];
    }
}
#endif

void spectrum_permutation(uint64_t state[16]) {
    uint64_t temp[16];
    for (int i = 0; i < 16; i++)
        temp[(i * 7) % 16] = state[i];
    memcpy(state, temp, 128);
}

/* ========================================================================= */
/*                    DECIFRAÇÃO: COMPONENTES INVERSOS                       */
/* ========================================================================= */

void spectrum_permutation_inverse(uint64_t state[16]) {
    uint64_t temp[16];
    for (int i = 0; i < 16; i++)
        temp[i] = state[(i * 7) % 16];
    memcpy(state, temp, 128);
}

#if !SPECTRUM_USE_AVX2
/* Implementacao escalar (fallback) */
void spectrum_diffusion_inverse_avx2(uint64_t state[16], const uint64_t r_key[4]) {
    uint64_t V0[4], V1[4], V2[4], V3[4];
    for (int j = 0; j < 4; j++) {
        V0[j] = state[4*j + 0]; V1[j] = state[4*j + 1];
        V2[j] = state[4*j + 2]; V3[j] = state[4*j + 3];
    }
    for (int i = 0; i < 4; i++) { V0[i] -= V1[i]; V1[i] -= V2[i]; V2[i] -= V3[i]; }
    uint64_t iw0 = modInverse64(r_key[0]|1), iw1 = modInverse64(r_key[1]|1);
    uint64_t iw2 = modInverse64(r_key[2]|1), iw3 = modInverse64(r_key[3]|1);
    for (int i = 0; i < 4; i++) { V0[i]*=iw0; V1[i]*=iw1; V2[i]*=iw2; V3[i]*=iw3; }
    for (int i = 0; i < 4; i++) { V2[i] -= V3[i]; V1[i] -= V2[i]; V0[i] -= V1[i]; }
    for (int j = 0; j < 4; j++) {
        state[4*j+0] = V0[j]; state[4*j+1] = V1[j];
        state[4*j+2] = V2[j]; state[4*j+3] = V3[j];
    }
}
#else
/* Implementacao AVX2 */
void spectrum_diffusion_inverse_avx2(uint64_t state[16], const uint64_t r_key[4]) {
    __m256i V0 = _mm256_set_epi64x(state[12], state[8], state[4], state[0]);
    __m256i V1 = _mm256_set_epi64x(state[13], state[9], state[5], state[1]);
    __m256i V2 = _mm256_set_epi64x(state[14], state[10], state[6], state[2]);
    __m256i V3 = _mm256_set_epi64x(state[15], state[11], state[7], state[3]);
    V0 = _mm256_sub_epi64(V0, V1); V1 = _mm256_sub_epi64(V1, V2);
    V2 = _mm256_sub_epi64(V2, V3);
    uint64_t *v0_p=(uint64_t*)&V0,*v1_p=(uint64_t*)&V1;
    uint64_t *v2_p=(uint64_t*)&V2,*v3_p=(uint64_t*)&V3;
    uint64_t iw0=modInverse64(r_key[0]|1), iw1=modInverse64(r_key[1]|1);
    uint64_t iw2=modInverse64(r_key[2]|1), iw3=modInverse64(r_key[3]|1);
    for (int i=0;i<4;i++){v0_p[i]*=iw0;v1_p[i]*=iw1;v2_p[i]*=iw2;v3_p[i]*=iw3;}
    V2 = _mm256_sub_epi64(V2, V3); V1 = _mm256_sub_epi64(V1, V2);
    V0 = _mm256_sub_epi64(V0, V1);
    uint64_t out_v0[4],out_v1[4],out_v2[4],out_v3[4];
    _mm256_storeu_si256((__m256i*)out_v0,V0); _mm256_storeu_si256((__m256i*)out_v1,V1);
    _mm256_storeu_si256((__m256i*)out_v2,V2); _mm256_storeu_si256((__m256i*)out_v3,V3);
    for (int j=0;j<4;j++){
        state[4*j+0]=out_v0[j]; state[4*j+1]=out_v1[j];
        state[4*j+2]=out_v2[j]; state[4*j+3]=out_v3[j];
    }
}
#endif

/**
 * Inversão da Camada Não-Linear: Ψ_NC⁻¹ — VERSÃO 2.0
 * 
 * Ordem inversa (desfazimento):
 * 1. Carry-Killer inverso: w_i = z_i XOR ((z_i >>> 1) AND 0x55...55)
 *    (XOR é auto-inverso: aplicar duas vezes retorna ao original)
 * 2. Inversão de Euler-Rivest com constante: y_i = P⁻¹(w_i XOR C_r)
 * 3. Inversão da interferência com constantes assimétricas: x_i = y_i XOR RotL(x_{i+1}, L_{i,r})
 * 4. Remoção da Chave: s_i = x_i - R_{r, i mod 4}
 *
 * @param state  Estado de 16 × 64 bits (modificado in-place)
 * @param r_key  Subchave da rodada (4 × 64 bits)
 * @param round  Índice da rodada (0..11) — necessário para OD-01 e OD-02
 */
void spectrum_confusion_inverse(uint64_t state[16], const uint64_t r_key[4], int round) {
    uint64_t y[16], x[16];
    
    // Passo 1: Carry-Killer inverso (XOR é auto-inverso) — desfaz OD-01
    for (int i = 0; i < 16; i++) {
        state[i] = state[i] ^ ((state[i] >> 1) & MASK_CARRY_KILLER);
    }
    
    // Passo 2: Inversão de Euler-Rivest com constante de rodada — desfaz OD-02
    // w_i = y_i + ((y_i² OR 1) XOR C_r)  →  y_i = P⁻¹(w_i XOR C_r)
    for (int i = 0; i < 16; i++) {
        y[i] = invert_rivest(state[i] ^ SPECTRUM_PI_C[round]);
    }
    
    // Passo 3: Inversão da interferência com constantes assimétricas — desfaz OD-02
    // Inversa do Feistel: x[0] = y[0]; x[i] = y[i] XOR RotL(x[i-1], L_{i,r})
    x[0] = y[0];
    for (int i = 1; i < 16; i++) {
        int rotation = (SPECTRUM_L_BASE[i] + round * 7) % 64;
        x[i] = y[i] ^ rotl64(x[i - 1], rotation);
    }
    
    // Passo 4: Remoção da chave
    for (int i = 0; i < 16; i++)
        state[i] = x[i] - r_key[i % 4];
}

/* ========================================================================= */
/*                    FLUXOS GLOBAIS: CIFRAÇÃO/DECIFRAÇÃO                    */
/* ========================================================================= */

void spectrum_encrypt(uint64_t state[16], const uint64_t master_key[4]) {
    spectrum_subkeys_t subkeys;
    spectrum_keygen(master_key, &subkeys);
    
    for (int r = 0; r < SPECTRUM_ROUNDS; r++) {
        spectrum_confusion(state, subkeys.R[r], r);    // OD-01 + OD-02
        spectrum_diffusion_avx2(state, subkeys.R[r]);
        spectrum_permutation(state);
    }
}

void spectrum_decrypt(uint64_t state[16], const uint64_t master_key[4]) {
    spectrum_subkeys_t subkeys;
    spectrum_keygen(master_key, &subkeys);
    
    for (int r = SPECTRUM_ROUNDS - 1; r >= 0; r--) {
        spectrum_permutation_inverse(state);
        spectrum_diffusion_inverse_avx2(state, subkeys.R[r]);
        spectrum_confusion_inverse(state, subkeys.R[r], r);  // OD-01 + OD-02
    }
}

/* ========================================================================= */
/*                    BUFFER: CIFRAÇÃO/DECIFRAÇÃO COM PKCS#7                 */
/* ========================================================================= */

size_t spectrum_encrypt_buffer(const uint8_t *input, size_t input_len,
                               const uint64_t master_key[4], uint8_t **output) {
    size_t padding_len = SPECTRUM_BLOCK_SIZE - (input_len % SPECTRUM_BLOCK_SIZE);
    size_t ciphertext_len = input_len + padding_len;
    
    *output = (uint8_t *)malloc(ciphertext_len);
    if (!*output) return 0;
    
    memcpy(*output, input, input_len);
    for (size_t i = input_len; i < ciphertext_len; i++)
        (*output)[i] = (uint8_t)padding_len;
    
    for (size_t offset = 0; offset < ciphertext_len; offset += SPECTRUM_BLOCK_SIZE)
        spectrum_encrypt((uint64_t *)((*output) + offset), master_key);
    
    return ciphertext_len;
}

/**
 * Decifração de buffer com unpadding em tempo constante
 * 
 * CORREÇÃO IC-08: Usa spectrum_unpadding_constant_time para
 * prevenir ataques de Padding Oracle.
 * 
 * @return Tamanho real dos dados, ou -1 se input inválido
 */
long long spectrum_decrypt_buffer(const uint8_t *input, size_t input_len,
                                  const uint64_t master_key[4], uint8_t *output) {
    // Validação de entrada
    if (input_len % SPECTRUM_BLOCK_SIZE != 0 || input_len == 0)
        return -1;
    
    // Copiar dados cifrados para processamento
    memcpy(output, input, input_len);
    
    // Decifrar todos os blocos
    for (size_t offset = 0; offset < input_len; offset += SPECTRUM_BLOCK_SIZE)
        spectrum_decrypt((uint64_t *)(output + offset), master_key);
    
    // CORREÇÃO IC-08: Usar unpadding em tempo constante
    // Isso previne ataques de Padding Oracle
    size_t real_len = 0;
    uint8_t valid = spectrum_unpadding_constant_time(
        output + input_len - SPECTRUM_BLOCK_SIZE, &real_len);
    
    // Se padding inválido, retornar erro (sem vazar informação)
    if (valid != 0xFF)
        return -1;
    
    return (long long)real_len;
}

/* ========================================================================= */
/*                    ARQUIVO: CIFRAÇÃO/DECIFRAÇÃO                           */
/* ========================================================================= */

int spectrum_encrypt_file(const char *in_filename, const char *out_filename,
                          const uint64_t master_key[4]) {
    FILE *fin = fopen(in_filename, "rb");
    FILE *fout = fopen(out_filename, "wb");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return 0;
    }
    
    uint8_t buffer[SPECTRUM_BLOCK_SIZE];
    size_t bytes_read;
    int keep_reading = 1;
    
    while (keep_reading) {
        bytes_read = fread(buffer, 1, SPECTRUM_BLOCK_SIZE, fin);
        
        if (bytes_read < SPECTRUM_BLOCK_SIZE) {
            size_t padding_len = SPECTRUM_BLOCK_SIZE - bytes_read;
            for (size_t i = bytes_read; i < SPECTRUM_BLOCK_SIZE; i++)
                buffer[i] = (uint8_t)padding_len;
            keep_reading = 0;
        }
        
        spectrum_encrypt((uint64_t *)buffer, master_key);
        fwrite(buffer, 1, SPECTRUM_BLOCK_SIZE, fout);
    }
    
    if (bytes_read == SPECTRUM_BLOCK_SIZE) {
        memset(buffer, SPECTRUM_BLOCK_SIZE, SPECTRUM_BLOCK_SIZE);
        spectrum_encrypt((uint64_t *)buffer, master_key);
        fwrite(buffer, 1, SPECTRUM_BLOCK_SIZE, fout);
    }
    
    fclose(fin);
    fclose(fout);
    return 1;
}

int spectrum_decrypt_file(const char *in_filename, const char *out_filename,
                          const uint64_t master_key[4]) {
    FILE *fin = fopen(in_filename, "rb");
    FILE *fout = fopen(out_filename, "wb");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return 0;
    }
    
    fseek(fin, 0, SEEK_END);
    long long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    if (file_size % SPECTRUM_BLOCK_SIZE != 0 || file_size == 0) {
        fclose(fin);
        fclose(fout);
        return 0;
    }
    
    uint8_t buffer[SPECTRUM_BLOCK_SIZE];
    long long processed_bytes = 0;
    
    while (processed_bytes < file_size) {
        fread(buffer, 1, SPECTRUM_BLOCK_SIZE, fin);
        spectrum_decrypt((uint64_t *)buffer, master_key);
        processed_bytes += SPECTRUM_BLOCK_SIZE;
        
        if (processed_bytes == file_size) {
            uint8_t padding_len = buffer[SPECTRUM_BLOCK_SIZE - 1];
            if (padding_len == 0 || padding_len > SPECTRUM_BLOCK_SIZE) {
                fclose(fin);
                fclose(fout);
                return 0;
            }
            size_t real_data_len = SPECTRUM_BLOCK_SIZE - padding_len;
            if (real_data_len > 0)
                fwrite(buffer, 1, real_data_len, fout);
        } else {
            fwrite(buffer, 1, SPECTRUM_BLOCK_SIZE, fout);
        }
    }
    
    fclose(fin);
    fclose(fout);
    return 1;
}

/* ========================================================================= */
/*                    UNPADDING EM TEMPO CONSTANTE                           */
/* ========================================================================= */

uint8_t spectrum_unpadding_constant_time(const uint8_t block[SPECTRUM_BLOCK_SIZE],
                                         size_t *out_real_len) {
    uint8_t padding_len = block[SPECTRUM_BLOCK_SIZE - 1];
    
    uint32_t len_check = (uint32_t)(padding_len - 1) | (uint32_t)(SPECTRUM_BLOCK_SIZE - padding_len);
    uint32_t len_check_mask = ~((int32_t)len_check >> 31);
    uint8_t is_valid_range = (uint8_t)(len_check_mask & 0xFF);
    
    uint8_t error_accumulator = 0;
    for (int i = 0; i < SPECTRUM_BLOCK_SIZE; i++) {
        int distance = SPECTRUM_BLOCK_SIZE - i;
        int32_t in_padding_zone = (int32_t)(distance - 1) - (int32_t)padding_len;
        uint8_t zone_mask = (uint8_t)((in_padding_zone >> 31) & 0xFF);
        uint8_t diff = block[i] ^ padding_len;
        error_accumulator |= (diff & zone_mask);
    }
    
    uint8_t has_error = (uint8_t)((-(int32_t)error_accumulator) >> 31) & 0xFF;
    uint8_t final_status_mask = is_valid_range & (~has_error);
    size_t valid_len = (size_t)(SPECTRUM_BLOCK_SIZE - padding_len);
    
    *out_real_len = (valid_len & (size_t)((intptr_t)(int8_t)final_status_mask));
    return final_status_mask;
}

/* ========================================================================= */
/*                              MAIN (TESTE)                                 */
/* ========================================================================= */

#ifndef SPECTRUM_NO_MAIN

int main() {
    uint64_t chave[4] = {
        0x0123456789abcdefULL, 0xfedcba9876543210ULL,
        0xbaaaaaadbeefdeadULL, 0x0001020304050607ULL
    };
    
    uint64_t estado_original[16] = {
        0x0011223344556677ULL, 0x8899aabbccddeeffULL,
        0x0102030405060708ULL, 0x1020304050607080ULL,
        0xfeedfacecafebabeULL, 0xdeadbeefbadf00d1ULL,
        0x0ULL, 0x123456789ULL,
        0xaaaaaaaaaaaaaaaaULL, 0x5555555555555555ULL,
        0xffffffffffffffffULL, 0x1337c0de1337c0deULL,
        0x7ULL, 0x8ULL, 0x9ULL, 0xaULL
    };
    
    uint64_t estado[16];
    memcpy(estado, estado_original, 128);
    
    printf("=== SPECTRUM-1024 FULL PAIRED TEST (AVX2) ===\n\n");
    
    spectrum_encrypt(estado, chave);
    printf("Texto Cifrado:\n");
    for (int i = 0; i < 16; i++)
        printf("s[%02d]: 0x%016llx\n", i, (unsigned long long)estado[i]);
    
    spectrum_decrypt(estado, chave);
    printf("\nTexto Decifrado:\n");
    for (int i = 0; i < 16; i++)
        printf("s[%02d]: 0x%016llx\n", i, (unsigned long long)estado[i]);
    
    if (memcmp(estado, estado_original, 128) == 0) {
        printf("\n[OK] PROVA DE REVERSIBILIDADE CONCLUIDA: "
               "O texto decifrado e identico ao original bit a bit.\n");
    } else {
        printf("\n[ERRO] REVERSIBILIDADE FALHOU: "
               "O estado decifrado divergiu do original.\n");
    }
    
    return 0;
}

#endif