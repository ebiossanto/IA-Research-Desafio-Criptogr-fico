# SPECTRUM-1024: O Desafio Criptográfico

## Categorias: Criptoanálise | Cipher Design | Block Cipher

**Dificuldade:** ★★★☆☆ (Médio)  
**Autor:** Euzebio Santos  
**Tags:** `spectrum`, `permutation`, `euler-rivest`, `new-cipher`

---

## Visão Geral

SPECTRUM-1024 é uma **permutação de 1024 bits** com chave de 256 bits e 12 rodadas. 
Diferente de cifras de bloco tradicionais, ela opera diretamente sobre o estado de 1024 bits 
usando uma combinação de:

- **Camada de Confusão (Ψ_NC):** Polinômio de Euler-Rivest `P(y) = y + (y² | 1)` com constantes derivadas de π
- **Camada de Difusão:** Laplaciana de Hodge com pesos modulares
- **Modificação OD-01:** Carry-Killers para interromper trilhas de transporte
- **Modificação OD-02:** Constantes assimétricas por rodada

## Arquivos Fornecidos

```
spectrum1024.h    - Header da implementação (público)
spectrum1024.c    - Implementação completa (público)
```

## Desafios

### Level 1 (Básico) — "A Flag está aí"

**Ciphertext:**
```
72fb7e3459cdd001c1a46d2cf50322971176df705111a361ef93d1eebac4f4adea7b4b87033831b5fb12efac9c56f43f1fa99692c83a8989fdb25533c6dff18080759f56e200885678395ac56602114693c80f17d0f7f00ac48e3b206b66af283d9e2b0b2576e7e7cc843707b064c9b6b76af667060463033e10d582a05b3054
```

**Dica:** O formato da flag é `FLAG{...}`. SPECTRUM-1024 é uma **permutação**, não uma cifra de bloco. Pense sobre o que isso significa.

**Pergunta:** Qual é a flag?

---

### Level 2 (Médio) — "O Oracle"

**Ciphertext:**
```
068938ea7e629305a7c63389c852d7ff3bd7675190fcc11fe434965fc52da91d0044f7640b9ae19f38696829d015ba488bac61dfb377e13c06384d65c8e71c8e154223b9eead7ee893a2113721d00b16bbd09094c01e47b2c52d96fa3b3402955702a8bae0accda37b8e6b80bdf60e41f6679ca130f92edf81c159fbed3a9675
```

**Dica:** A chave de cifragem é desconhecida. A implementação está disponível. Analise a estrutura do polinômio de Euler-Rivest. Ele realmente inverte corretamente com Newton-Raphson para **todos** os valores iniciais?

**Pergunta:** Qual é a flag?

---

### Level 3 (Expert) — "Nonce Leak"

**Ciphertext:**
```
805d2b43e59252d031c6e2e256ef4e4e15f453b171ebd02a506176fd8be6bca979ec4238e8a4f22545ab25a71f8dd215080a16dc6c66966abd31b4202f6b282d12f4b740d4f9ff423d57d02d80460b5ba098f54a479f20c789b8b26a9dc2aa3141147773028ef2df5097279e6e0a3a77b775511e351e504627cdd33235bc2f44
```

**Nonce (fornecido):**
```
41424344454647483132333435363738deadbeefcafebabe0123456789abcdef
```

**Dica:** O plaintext foi XOR-combinado com o nonce **antes** da cifragem. A chave é a mesma dos levels anteriores. Combine as informações dos níveis anteriores.

**Pergunta:** Qual é a flag?

---

## Dados para Análise Estatística

Abaixo, 16 pares plaintext-ciphertext com chave = 0 (todos zeros):

| # | PT (hex) | CT (primeiros 16 bytes) |
|---|----------|------------------------|
| 0 | `0000000000000000` | `00cd8f3670975961` |
| 1 | `0000000000000001` | `e1fd2361a48649c4` |
| 2 | `0000000000000002` | `7749f902cd0569eb` |
| 3 | `0000000000000003` | `7e4758a113303e80` |
| 4 | `0000000000000004` | `66324bbe74677aef` |
| 5 | `0000000000000005` | `635bc28ccec22ead` |
| 6 | `0000000000000006` | `9a25bc12fda363b1` |
| 7 | `0000000000000007` | `e2bf9004695a0d95` |
| 8 | `0000000000000008` | `57c22d81d34a6c90` |
| 9 | `0000000000000009` | `b94c044451bc29ef` |
| 10 | `000000000000000a` | `865e50c663679318` |
| 11 | `000000000000000b` | `dd814a220497efb9` |
| 12 | `000000000000000c` | `a589f31c5ced8b5b` |
| 13 | `000000000000000d` | `0b03a2c9854a4b3b` |
| 14 | `000000000000000e` | `c4a647f5f8fce49e` |
| 15 | `000000000000000f` | `2782c63748b5f100` |

---

## Formato da Resposta

Todas as flags seguem o formato: `FLAG{...}`

**Level 1:** `FLAG{...}`  
**Level 2:** `FLAG{...}`  
**Level 3:** `FLAG{...}`

---

## Pistas (liberadas após 24h)

### Pista 1
> SPECTRUM-1024 é uma **permutação**, não uma cifra de bloco no sentido tradicional. 
> Ela mapeia 1024 bits → 1024 bits de forma bijectiva. O que isso implica sobre a relação entre plaintext e ciphertext?

### Pista 2
> O polinômio de Euler-Rivest é `P(y) = y + (y² | 1)`. A inversão usa Newton-Raphson com o chute inicial `y₀ = z`. 
> Verifique: `P(0) = 1`. Se `z = 1`, o Newton-Raphson converge para o valor correto?

### Pista 3
> Para o Level 3, lembre que `XOR(A, B)` depois `SPECTRUM_encrypt(K)` é equivalente a 
> `SPECTRUM_encrypt(K ⊕ something)`. A permutação com chave zero é determinística.

---

## Sobre o Cipher

SPECTRUM-1024 foi desenvolvido como contribuição acadêmica para criptografia simétrica.
As modificações OD-01 (Carry-Killers) e OD-02 (Constantes Assimétricas) foram projetadas 
para fortalecer a camada de confusão contra ataques diferenciais e lineares.

O desafio testa se a implementação correta das inversões (que é fundamental para o Decodificador) 
funciona para todos os casos.

**Boa sorte!**
