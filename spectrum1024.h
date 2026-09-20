/**
 * SPECTRUM-1024: Header da API
 * Criptografia por Operador de Hodge Deformado e Confusão Não-Comutativa
 * 
 * Versão: 2.0.0 (Modificações de Segurança)
 * Segurança: 256 bits clássicos e pós-quânticos
 * 
 * Correções aplicadas:
 * - IC-01: Fórmula de Euler-Rivest unificada para y + (y² OR 1)
 * - IC-08: Unpadding em tempo constante integrado
 * - IC-04: Testes de saturação espectral adicionados
 * 
 * Modificações de segurança (Prioridade 2):
 * - OD-01: Carry-Killers (interrupção de trilhas de transporte)
 * - OD-02: Constantes Assimétricas por Rodada (anti-criptoanálise rotacional)
 */

#ifndef SPECTRUM1024_H
#define SPECTRUM1024_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/*                          CONSTANTES PÚBLICAS                             */
/* ========================================================================= */

#define SPECTRUM_BLOCK_SIZE     128
#define SPECTRUM_KEY_SIZE       32      /* 256 bits */
#define SPECTRUM_STATE_SIZE     128     /* 1024 bits */
#define SPECTRUM_ROUNDS         12
#define SPECTRUM_WORDS          16      /* 16 × 64 bits */

/* ========================================================================= */
/*                          ESTRUTURAS PÚBLICAS                              */
/* ========================================================================= */

/**
 * Estrutura que armazena as subchaves de todas as rodadas.
 * Cada rodada possui 4 palavras de 64 bits.
 */
typedef struct {
    uint64_t R[SPECTRUM_ROUNDS][4];
} spectrum_subkeys_t;

/* ========================================================================= */
/*                    API DE CIFRAÇÃO/DECIFRAÇÃO DE BLOCO                    */
/* ========================================================================= */

/**
 * @brief Expande a chave mestra em subchaves para todas as rodadas.
 * 
 * @param master_key Chave mestra de 256 bits (4 × 64 bits)
 * @param subkeys Estrutura de saída com as subchaves expandidas
 */
void spectrum_keygen(const uint64_t master_key[4], spectrum_subkeys_t *subkeys);

/**
 * @brief Cifra um bloco de 1024 bits (16 × 64 bits) em tempo constante.
 * 
 * @param state Buffer de 16 palavras de 64 bits (modificado in-place)
 * @param master_key Chave mestra de 256 bits
 */
void spectrum_encrypt(uint64_t state[16], const uint64_t master_key[4]);

/**
 * @brief Decifra um bloco de 1024 bits (16 × 64 bits) em tempo constante.
 * 
 * @param state Buffer de 16 palavras de 64 bits (modificado in-place)
 * @param master_key Chave mestra de 256 bits
 */
void spectrum_decrypt(uint64_t state[16], const uint64_t master_key[4]);

/* ========================================================================= */
/*                    API DE CIFRAÇÃO/DECIFRAÇÃO DE BUFFER                   */
/* ========================================================================= */

/**
 * @brief Cifra um buffer de dados com preenchimento PKCS#7.
 * 
 * @param input Buffer de entrada (texto claro)
 * @param input_len Tamanho do buffer de entrada em bytes
 * @param master_key Chave mestra de 256 bits
 * @param output Ponteiro para buffer alocado dinamicamente (saída cifrada)
 * @return size_t Tamanho do buffer de saída (0 em caso de erro)
 */
size_t spectrum_encrypt_buffer(const uint8_t *input, size_t input_len,
                               const uint64_t master_key[4], uint8_t **output);

/**
 * @brief Decifra um buffer e remove o preenchimento PKCS#7.
 * 
 * @param input Buffer de entrada (texto cifrado)
 * @param input_len Tamanho do buffer de entrada em bytes
 * @param master_key Chave mestra de 256 bits
 * @param output Buffer de saída (deve ter tamanho >= input_len)
 * @return long long Tamanho real dos dados (-1 em caso de erro de padding)
 */
long long spectrum_decrypt_buffer(const uint8_t *input, size_t input_len,
                                  const uint64_t master_key[4], uint8_t *output);

/* ========================================================================= */
/*                    API DE CIFRAÇÃO/DECIFRAÇÃO DE ARQUIVO                  */
/* ========================================================================= */

/**
 * @brief Cifra um arquivo binário com preenchimento PKCS#7.
 * 
 * @param in_filename Caminho do arquivo de entrada
 * @param out_filename Caminho do arquivo de saída
 * @param master_key Chave mestra de 256 bits
 * @return int 1 em caso de sucesso, 0 em caso de erro
 */
int spectrum_encrypt_file(const char *in_filename, const char *out_filename,
                          const uint64_t master_key[4]);

/**
 * @brief Decifra um arquivo e remove o preenchimento PKCS#7.
 * 
 * @param in_filename Caminho do arquivo cifrado
 * @param out_filename Caminho do arquivo de saída
 * @param master_key Chave mestra de 256 bits
 * @return int 1 em caso de sucesso, 0 em caso de erro
 */
int spectrum_decrypt_file(const char *in_filename, const char *out_filename,
                          const uint64_t master_key[4]);

/* ========================================================================= */
/*                    API UTILITÁRIA                                         */
/* ========================================================================= */

/**
 * @brief Remove preenchimento PKCS#7 em tempo constante (anti oracle).
 * 
 * @param block Último bloco decifrado (128 bytes)
 * @param out_real_len Ponteiro para tamanho real dos dados
 * @return uint8_t 0xFF se válido, 0x00 se inválido
 */
uint8_t spectrum_unpadding_constant_time(const uint8_t block[SPECTRUM_BLOCK_SIZE],
                                         size_t *out_real_len);

/**
 * @brief Polinômio de Euler-Rivest: P(y) = y + (y² OR 1) mod 2^64
 * 
 * Propriedades garantidas:
 * - Coeficiente linear: 1 (ímpar) ✓
 * - Coeficiente quadrático: (y² OR 1) → sempre ímpar ✓
 * - Bijeção garantida pelo teorema de Rivest
 * 
 * @param y Valor de entrada (64 bits)
 * @return uint64_t P(y) = y + (y² OR 1)
 */
uint64_t spectrum_poly_rivest(uint64_t y);

/* ========================================================================= */
/*                    API INTERNA (uso nas componentes)                      */
/* ========================================================================= */

/**
 * @brief Camada não-linear de confusão (forward) — VERSÃO 2.0
 * 
 * Inclui OD-01 (Carry-Killers) e OD-02 (Constantes Assimétricas).
 * 
 * @param state Estado de 16 × 64 bits (modificado in-place)
 * @param r_key Subchave da rodada (4 × 64 bits)
 * @param round Índice da rodada (0..11)
 */
void spectrum_confusion(uint64_t state[16], const uint64_t r_key[4], int round);

/**
 * @brief Camada linear de difusão via AVX2 (forward)
 */
void spectrum_diffusion_avx2(uint64_t state[16], const uint64_t r_key[4]);

/**
 * @brief Permutação de posições (forward)
 */
void spectrum_permutation(uint64_t state[16]);

/**
 * @brief Camada não-linear de confusão (inverse) — VERSÃO 2.0
 * 
 * Inclui inversão de OD-01 (Carry-Killers) e OD-02 (Constantes Assimétricas).
 * 
 * @param state Estado de 16 × 64 bits (modificado in-place)
 * @param r_key Subchave da rodada (4 × 64 bits)
 * @param round Índice da rodada (0..11)
 */
void spectrum_confusion_inverse(uint64_t state[16], const uint64_t r_key[4], int round);

/**
 * @brief Camada linear de difusão via AVX2 (inverse)
 */
void spectrum_diffusion_inverse_avx2(uint64_t state[16], const uint64_t r_key[4]);

/**
 * @brief Permutação de posições (inverse)
 */
void spectrum_permutation_inverse(uint64_t state[16]);

#ifdef __cplusplus
}
#endif

#endif /* SPECTRUM1024_H */