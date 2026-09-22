# Desafio Criptográfico: SPECTRUM-1024 & CifraTeste-1024

## Sobre Este Projeto

> **Nota:** Estes trabalhos sao estudos de ideias desenvolvidos com ferramentas de inteligencia artificial. O autor e um estudante, entusiasta e pesquisador com um brinquedo nas maos.

**Ferramentas utilizadas:** Gemini MiMo V2.5, GPT 5.6 Copilot, Opencode

**Autor:** Euzébio Soares dos Santos — Estudante, entusiasta e pesquisador

## Sobre Este Repositório

Dois desafios de criptoanálise baseados em cifras de bloco de 1024 bits desenvolvidas como pesquisa acadêmica.

---

## Desafio 1: SPECTRUM-1024

**Categorias:** Criptoanálise | Permutation | Euler-Rivest  
**Dificuldade:** ★★★☆☆ (Médio)

SPECTRUM-1024 é uma **permutação de 1024 bits** com chave de 256 bits e 12 rodadas. Opera usando polinômio de Euler-Rivest, Laplaciana de Hodge, e Carry-Killers.

### Levels

| Level | Título | Conceito Testado |
|-------|--------|------------------|
| 1 | "A Flag está aí" | Permutação vs cifra de bloco |
| 2 | "O Oracle" | Convergência de Newton-Raphson |
| 3 | "Nonce Leak" | XOR antes da cifragem |

**Arquivos:** `spectrum1024.h`, `spectrum1024.c`, `challenge.c`, `DESAFIO_PUBLICO.md`

---

## Desafio 2: CifraTeste-1024

**Categorias:** Criptoanálise | SPN Block Cipher | GF(2⁸)  
**Dificuldade:** ★★★☆☆ (Médio)

CifraTeste-1024 é uma **cifra SPN (Substitution-Permutation Network)** com:
- **Bloco:** 1024 bits | **Chave:** 256 bits | **Rodadas:** 16
- **SubBytes:** S-box AES (não-linearidade 112)
- **MixColumns:** Matriz MDS [2,3,1,1] em GF(2⁸)
- **Key Schedule:** Blake3-inspired CVB

### Levels

| Level | Título | Conceito Testado |
|-------|--------|------------------|
| 1 | "Chave Pública" | Chave pública = 0, decifrar trivial |
| 2 | "Invertendo o CVB" | Key schedule inversão |
| 3 | "XOR Linear" | Linearidade do MixColumns |

**Arquivos:** `cifrateste1024.h`, `cifrateste1024.c`, `challenge_cifrateste.c`, `DESAFIO_PUBLICO.md`

---

## Análise Criptográfica

| Propriedade | SPECTRUM-1024 | CifraTeste-1024 |
|-------------|---------------|-----------------|
| Tipo | Permutação | SPN Block Cipher |
| Bloco | 1024 bits | 1024 bits |
| Chave | 256 bits | 256 bits |
| Rodadas | 12 | 16 |
| S-box | Polinômio Euler-Rivest | AES S-box (8-bit) |
| Difusão | Laplaciana de Hodge | MDS [2,3,1,1] GF(2⁸) |
| Seg. Diferencial | ~96 bits | ~96 bits |
| Seg. Linear | ~48 bits | ~48 bits |

---

## Como Usar

### Compilar (TCC no Windows)

```bash
# SPECTRUM-1024
tcc -DSPECTRUM_NO_MAIN -c spectrum1024.c -o spectrum1024.obj
tcc challenge.c spectrum1024.obj -o challenge.exe

# CifraTeste-1024
tcc -I src_v2 -c cifrateste1024.c -o cifrateste1024.obj
tcc -I src_v2 challenge_cifrateste.c cifrateste1024.obj -o challenge_cifrateste.exe
```

### Executar

```bash
# Gerar ciphertexts
challenge.exe generate

# Cifrar/Decifrar
challenge.exe encrypt <key_hex> <plaintext>
challenge.exe decrypt <key_hex> <ciphertext_hex>

# Oracle (chave = 0)
challenge.exe oracle encrypt
```

---

## Formato das Flags

Todas as flags seguem: `FLAG{...}`

---

## Autor

**Euzébio Soares dos Santos** — Pesquisa em criptografia simétrica e matemática computacional.

---

## Licença

MIT License
