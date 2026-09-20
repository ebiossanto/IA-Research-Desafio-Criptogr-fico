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

static const uint64_t SECRET_KEY[4] = {
    0xdeadbeefcafebabeULL,
    0x0123456789abcdefULL,
    0xfedcba9876543210ULL,
    0x0011223344556677ULL
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("=== CIFRATESTE-1024 CHALLENGE GENERATOR ===\n");
        printf("Uso:\n");
        printf("  %s generate    - Gerar todos os ciphertexts\n", argv[0]);
        printf("  %s encrypt     - Cifrar com chave secreta\n", argv[0]);
        printf("  %s decrypt     - Decifrar com chave secreta\n", argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "generate") == 0) {
        printf("=== GERADOR DE DESAFIO CIFRATESTE-1024 ===\n\n");

        /* === Level 1: Chave publica (zeros) === */
        printf("[L1] Chave publica do oracle:\n  ");
        uint64_t zero_key[4] = {0};
        print_hex(zero_key, 4);
        printf("\n\n");

        /* Gerar 16 pares PT-CT com chave publica = 0 */
        printf("[L1] Dados para analise (16 pares PT-CT, chave=0):\n");
        for (int i = 0; i < 16; i++) {
            uint64_t pt[16] = {0};
            pt[0] = (uint64_t)i;
            uint64_t ct[16];
            memcpy(ct, pt, 128);
            ct_encrypt(ct, zero_key);
            printf("  PT[%2d]=%016llx -> CT=", i, (unsigned long long)pt[0]);
            print_hex(ct, 2);
            printf("\n");
        }
        printf("\n");

        /* === Level 1: Flag 1 === */
        const char *flag1 = "FLAG{cifrateste_spn_eh_um_bom_exemplo_de_cifra_de_bloco}";
        uint64_t state1[16] = {0};
        size_t len1 = strlen(flag1);
        memcpy(state1, flag1, len1);
        uint8_t *bytes1 = (uint8_t *)state1;
        uint8_t pad1 = (uint8_t)(128 - len1);
        for (size_t i = len1; i < 128; i++) bytes1[i] = pad1;
        ct_encrypt(state1, zero_key);

        printf("[L1] Flag 1 (Basico - chave publica = 0):\n  ");
        print_hex(state1, 16);
        printf("\n");
        printf("  Formato: FLAG{...}\n");
        printf("  Chave usada: ");
        print_hex(zero_key, 4);
        printf("\n\n");

        /* === Level 2: Flag 2 (chave secreta) === */
        const char *flag2 = "FLAG{key_schedule_cvb_pode_ser_invertido_se_voce_sabe_um_round_key}";
        uint64_t state2[16] = {0};
        size_t len2 = strlen(flag2);
        memcpy(state2, flag2, len2);
        uint8_t *bytes2 = (uint8_t *)state2;
        uint8_t pad2 = (uint8_t)(128 - len2);
        for (size_t i = len2; i < 128; i++) bytes2[i] = pad2;
        ct_encrypt(state2, SECRET_KEY);

        printf("[L2] Flag 2 (Medio - chave secreta):\n  ");
        print_hex(state2, 16);
        printf("\n");
        printf("  Formato: FLAG{...}\n\n");

        /* === Level 2: Dica - um round key conhecido === */
        ct_subkeys_t subkeys;
        ct_keygen(SECRET_KEY, &subkeys);
        printf("[L2] Dica: Round key #15 (ultima subchave):\n  ");
        print_hex(subkeys.round_keys[15], 16);
        printf("\n\n");

        /* === Level 3: Flag 3 (chave secreta, XOR com nonce) === */
        const char *flag3 = "FLAG{gf28_mix_columns_e_um_operador_linear_sobre_o_estado}";
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
        ct_encrypt(state3, SECRET_KEY);

        printf("[L3] Flag 3 (Expert - XOR nonce + chave secreta):\n  ");
        print_hex(state3, 16);
        printf("\n");
        printf("  Formato: FLAG{...} XOR nonce_antes_de_cifrar\n");
        printf("  Nonce (hex): ");
        print_hex(nonce, 4);
        printf("\n");
        printf("  Chave: mesma do Level 2\n\n");

        /* Dados para analise estatistica com chave secreta */
        printf("[L3] Dados para analise (16 pares PT-CT, chave secreta):\n");
        for (int i = 0; i < 16; i++) {
            uint64_t pt[16] = {0};
            pt[0] = (uint64_t)i;
            uint64_t ct[16];
            memcpy(ct, pt, 128);
            ct_encrypt(ct, SECRET_KEY);
            printf("  PT[%2d]=%016llx -> CT=", i, (unsigned long long)pt[0]);
            print_hex(ct, 2);
            printf("\n");
        }
        printf("\n");

        /* S-box e inverse S-box para analise */
        printf("[INFO] S-box (primeiros 16 valores):\n  ");
        const uint8_t *sb = ct_get_sbox();
        for (int i = 0; i < 16; i++) printf("%02x ", sb[i]);
        printf("\n\n");

        printf("[INFO] Inverse S-box (primeiros 16 valores):\n  ");
        const uint8_t *isb = ct_get_inv_sbox();
        for (int i = 0; i < 16; i++) printf("%02x ", isb[i]);
        printf("\n\n");

        /* Verificar se round-trip funciona */
        printf("[VERIFY] Round-trip test: ");
        uint64_t test[16] = {0xDEADBEEFCAFEBABEULL};
        uint64_t orig[16];
        memcpy(orig, test, 128);
        ct_encrypt(test, SECRET_KEY);
        ct_decrypt(test, SECRET_KEY);
        printf("%s\n\n", memcmp(test, orig, 128) == 0 ? "OK" : "FAIL");
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

    printf("Parametros invalidos.\n");
    return 1;
}
