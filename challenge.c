#define SPECTRUM_NO_MAIN
#include "spectrum1024.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static void print_hex(const uint64_t *state, int n) {
    for (int i = 0; i < n; i++)
        printf("%016llx", (unsigned long long)state[i]);
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, uint64_t *out, int max_words) {
    int len = strlen(hex);
    if (len % 16 != 0 || len / 16 > max_words) return -1;
    int n = len / 16;
    for (int i = 0; i < n; i++) {
        out[i] = 0;
        for (int j = 0; j < 16; j++) {
            int d = hex_digit(hex[i * 16 + j]);
            if (d < 0) return -1;
            out[i] = (out[i] << 4) | d;
        }
    }
    return n;
}

/* ================================================================
 *  SERVIDOR DO DESAFIO
 *  
 *  Modo 1: Oracle de cifragem (envia plaintext, recebe ciphertext)
 *  Modo 2: Decodificador (envia ciphertext, recebe plaintext)
 *  Modo 3: Verificador de flag (envia flag candidata)
 *  
 *  A flag esta cifrada com a chave secreta FLAG_KEY.
 *  O jogador precisa descobrir a flag usando o oracle.
 * ================================================================ */

/* Chave secreta do desafio */
static const uint64_t FLAG_KEY[4] = {
    0xa3f1d829c04b6e57ULL,
    0x71b2e4f09d853a6cULL,
    0xd5e90f3a816724beULL,
    0x3c84a716f2db59e0ULL
};

/* Flag cifrada (pre-computada) */
static const uint64_t ENCRYPTED_FLAG[16] = {
    0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL,
    0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL,
    0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL,
    0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL
};

static void generate_encrypted_flag(void) {
    uint64_t state[16] = {0};
    const char *flag = "FLAG{sp3ctrum_1s_n0t_s0_s3cur3_wh3n_th3_1nv3rs3_c0nv3rg3s_b4dly}";
    size_t len = strlen(flag);
    if (len > 127) len = 127;
    memcpy(state, flag, len);
    uint8_t *bytes = (uint8_t *)state;
    uint8_t pad = (uint8_t)(128 - len);
    for (size_t i = len; i < 128; i++)
        bytes[i] = pad;
    
    spectrum_encrypt(state, FLAG_KEY);
    
    printf("ENCRYPTED_FLAG=");
    print_hex(state, 16);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("=== SPECTRUM-1024 CRYPTO CHALLENGE ===\n");
        printf("Uso:\n");
        printf("  %s encrypt <key_hex> <plaintext>    - Cifrar\n", argv[0]);
        printf("  %s decrypt <key_hex> <ciphertext_hex> - Decifrar\n", argv[0]);
        printf("  %s oracle                             - Modo oracle (stdin)\n", argv[0]);
        printf("  %s generate-flag                      - Gerar flag cifrada\n", argv[0]);
        printf("  %s check <flag>                       - Verificar flag\n", argv[0]);
        return 0;
    }
    
    if (strcmp(argv[1], "generate-flag") == 0) {
        generate_encrypted_flag();
        return 0;
    }
    
    if (strcmp(argv[1], "encrypt") == 0 && argc >= 4) {
        uint64_t key[4], state[16] = {0};
        if (parse_hex(argv[2], key, 4) != 4) {
            printf("ERRO: chave deve ter 64 hex chars\n");
            return 1;
        }
        size_t len = strlen(argv[3]);
        if (len > 127) len = 127;
        memcpy(state, argv[3], len);
        uint8_t *bytes = (uint8_t *)state;
        uint8_t pad = (uint8_t)(128 - len);
        for (size_t i = len; i < 128; i++)
            bytes[i] = pad;
        
        spectrum_encrypt(state, key);
        printf("CIPHERTEXT=");
        print_hex(state, 16);
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[1], "decrypt") == 0 && argc >= 4) {
        uint64_t key[4], state[16];
        if (parse_hex(argv[2], key, 4) != 4) {
            printf("ERRO: chave deve ter 64 hex chars\n");
            return 1;
        }
        if (parse_hex(argv[3], state, 16) != 16) {
            printf("ERRO: ciphertext deve ter 256 hex chars\n");
            return 1;
        }
        spectrum_decrypt(state, key);
        /* Print as text */
        char *text = (char *)state;
        int len = 128;
        while (len > 0 && text[len - 1] == 0) len--;
        if (len > 0) {
            uint8_t pad = ((uint8_t*)state)[len - 1];
            if (pad > 0 && pad <= 128) len -= pad;
        }
        printf("PLAINTEXT=");
        for (int i = 0; i < len; i++) {
            if (text[i] >= 32 && text[i] < 127)
                printf("%c", text[i]);
            else
                printf("\\x%02x", (unsigned char)text[i]);
        }
        printf("\n");
        return 0;
    }
    
    printf("Parametros invalidos. Use %s sem argumentos para ajuda.\n", argv[0]);
    return 1;
}
