#define CT_NO_MAIN 1
#include "cifrateste1024.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

static const uint64_t FLAG_KEY[4] = {
    0xdeadbeefcafebabeULL,
    0x0123456789abcdefULL,
    0xfedcba9876543210ULL,
    0x0011223344556677ULL
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("=== CIFRATESTE-1024 CRYPTO CHALLENGE ===\n");
        printf("Uso:\n");
        printf("  %s encrypt <key_hex> <plaintext>      - Cifrar\n", argv[0]);
        printf("  %s decrypt <key_hex> <ciphertext_hex> - Decifrar\n", argv[0]);
        printf("  %s oracle <mode>                       - Modo oracle (stdin)\n", argv[0]);
        printf("  %s check <flag>                        - Verificar flag\n", argv[0]);
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
        for (size_t i = len; i < 128; i++) bytes[i] = pad;
        ct_encrypt(state, key);
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
        ct_decrypt(state, key);
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

    if (strcmp(argv[1], "oracle") == 0 && argc >= 3) {
        char line[1024];
        if (strcmp(argv[2], "encrypt") == 0) {
            printf("Oracle encrypt mode (key=0). Enter plaintext (hex):\n");
            while (fgets(line, sizeof(line), stdin)) {
                line[strcspn(line, "\r\n")] = 0;
                if (strlen(line) == 0) break;
                uint64_t key[4] = {0};
                uint64_t state[16] = {0};
                int nwords = parse_hex(line, state, 16);
                if (nwords < 0) { printf("ERRO: invalid hex\n"); continue; }
                ct_encrypt(state, key);
                printf("CT=");
                print_hex(state, 16);
                printf("\n");
            }
        } else if (strcmp(argv[2], "decrypt") == 0) {
            printf("Oracle decrypt mode (key=0). Enter ciphertext (hex):\n");
            while (fgets(line, sizeof(line), stdin)) {
                line[strcspn(line, "\r\n")] = 0;
                if (strlen(line) == 0) break;
                uint64_t key[4] = {0};
                uint64_t state[16];
                if (parse_hex(line, state, 16) != 16) { printf("ERRO: need 256 hex chars\n"); continue; }
                ct_decrypt(state, key);
                char *text = (char *)state;
                int len = 128;
                while (len > 0 && text[len - 1] == 0) len--;
                if (len > 0) {
                    uint8_t pad = ((uint8_t*)state)[len - 1];
                    if (pad > 0 && pad <= 128) len -= pad;
                }
                printf("PT=");
                for (int i = 0; i < len; i++) {
                    if (text[i] >= 32 && text[i] < 127)
                        printf("%c", text[i]);
                    else
                        printf("\\x%02x", (unsigned char)text[i]);
                }
                printf("\n");
            }
        } else if (strcmp(argv[2], "key") == 0) {
            printf("Oracle key recovery mode.\n");
            printf("Enter round_key_15 (256 hex chars):\n");
            while (fgets(line, sizeof(line), stdin)) {
                line[strcspn(line, "\r\n")] = 0;
                if (strlen(line) == 0) break;
                uint64_t rk15[16];
                if (parse_hex(line, rk15, 16) != 16) { printf("ERRO: need 256 hex chars\n"); continue; }
                printf("ROUND_KEY_15=");
                print_hex(rk15, 16);
                printf("\n");
                printf("(Reverse CVB to recover master key - this is your challenge)\n");
            }
        }
        return 0;
    }

    if (strcmp(argv[1], "check") == 0 && argc >= 3) {
        if (strcmp(argv[2], "FLAG{cifrateste_spn_eh_um_bom_exemplo_de_cifra_de_bloco}") == 0) {
            printf("CORRETO (Level 1)!\n");
        } else if (strcmp(argv[2], "FLAG{key_schedule_cvb_pode_ser_invertido_se_voce_sabe_um_round_key}") == 0) {
            printf("CORRETO (Level 2)!\n");
        } else if (strcmp(argv[2], "FLAG{gf28_mix_columns_e_um_operador_linear_sobre_o_estado}") == 0) {
            printf("CORRETO (Level 3)! Parabens, voce completou todos os niveis!\n");
        } else {
            printf("INCORRETO. Tente novamente.\n");
        }
        return 0;
    }

    printf("Parametros invalidos. Use %s sem argumentos para ajuda.\n", argv[0]);
    return 1;
}
