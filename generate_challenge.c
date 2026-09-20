#define SPECTRUM_NO_MAIN
#include "spectrum1024.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void print_hex(const uint64_t *state, int n) {
    for (int i = 0; i < n; i++)
        printf("%016llx", (unsigned long long)state[i]);
}

int main(void) {
    printf("=== GERADOR DE DESAFIO SPECTRUM-1024 ===\n\n");
    
    /* Chave secreta */
    uint64_t key[4] = {
        0xa3f1d829c04b6e57ULL,
        0x71b2e4f09d853a6cULL,
        0xd5e90f3a816724beULL,
        0x3c84a716f2db59e0ULL
    };
    
    printf("[秘密] Chave secreta (NAO publicar!):\n  ");
    print_hex(key, 4);
    printf("\n\n");
    
    /* Gerar chave publica (usada para o oracle) */
    printf("[公开] Chave publica do oracle (fornecida aos jogadores):\n  ");
    uint64_t pub_key[4] = {0};
    print_hex(pub_key, 4);
    printf("\n\n");
    
    /* Flag 1: Mensagem simples */
    const char *flag1 = "FLAG{spectrum_eh_um_permutacao_nao_um_cipher_de_bloco}";
    uint64_t state1[16] = {0};
    size_t len1 = strlen(flag1);
    memcpy(state1, flag1, len1);
    uint8_t *bytes1 = (uint8_t *)state1;
    uint8_t pad1 = (uint8_t)(128 - len1);
    for (size_t i = len1; i < 128; i++) bytes1[i] = pad1;
    spectrum_encrypt(state1, key);
    
    printf("[CIFRADO] Flag 1 (Level 1 - Basico):\n  ");
    print_hex(state1, 16);
    printf("\n");
    printf("  Formato conhecido: FLAG{...}\n");
    printf("  Tamanho: %zu bytes\n\n", len1);
    
    /* Flag 2: Mensagem com estrutura unknown */
    const char *flag2 = "FLAG{voce_encontrou_o_euler_rivest_mas_eh_um_pol_inomo_nao_uma_bijecao_trivial}";
    uint64_t state2[16] = {0};
    size_t len2 = strlen(flag2);
    memcpy(state2, flag2, len2);
    uint8_t *bytes2 = (uint8_t *)state2;
    uint8_t pad2 = (uint8_t)(128 - len2);
    for (size_t i = len2; i < 128; i++) bytes2[i] = pad2;
    spectrum_encrypt(state2, key);
    
    printf("[CIFRADO] Flag 2 (Level 2 - Difcil):\n  ");
    print_hex(state2, 16);
    printf("\n");
    printf("  Formato: FLAG{...}\n");
    printf("  Tamanho: %zu bytes\n\n", len2);
    
    /* Flag 3: Com nonce XOR ( ECB-like com XOR ) */
    const char *flag3 = "FLAG{carry_killers_quebram_a_difusao_linear}";
    uint64_t nonce[4] = {0x4142434445464748ULL, 0x3132333435363738ULL,
                         0xdeadbeefcafebabeULL, 0x0123456789abcdefULL};
    uint64_t state3[16] = {0};
    size_t len3 = strlen(flag3);
    memcpy(state3, flag3, len3);
    uint8_t *bytes3 = (uint8_t *)state3;
    uint8_t pad3 = (uint8_t)(128 - len3);
    for (size_t i = len3; i < 128; i++) bytes3[i] = pad3;
    /* XOR com nonce no primeiro bloco */
    for (int i = 0; i < 4; i++)
        state3[i] ^= nonce[i];
    spectrum_encrypt(state3, key);
    
    printf("[CIFRADO] Flag 3 (Level 3 - Expert):\n  ");
    print_hex(state3, 16);
    printf("\n");
    printf("  Formato: FLAG{...} XOR nonce_antes_de_cifrar\n");
    printf("  Nonce fornecido (hex): ");
    print_hex(nonce, 4);
    printf("\n");
    printf("  Tamanho: %zu bytes\n\n", len3);
    
    /* Dados para analise estatistica */
    printf("=== DADOS PARA ANALISE ===\n");
    printf("Abaixo, 16 pares plaintext-ciphertext (chave publica = zeros):\n\n");
    
    uint64_t zero_key[4] = {0};
    for (int i = 0; i < 16; i++) {
        uint64_t pt[16] = {0};
        pt[0] = (uint64_t)i;
        uint64_t ct[16];
        memcpy(ct, pt, 128);
        spectrum_encrypt(ct, zero_key);
        printf("PT[%2d]=%016llx -> CT=", i, (unsigned long long)pt[0]);
        print_hex(ct, 2);
        printf("\n");
    }
    
    return 0;
}
