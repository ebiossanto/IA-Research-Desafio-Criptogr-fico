#!/usr/bin/env python3
"""
SPECTRUM-1024 Challenge Server
Modo: Encryption Oracle + Decryption
"""
import subprocess
import sys
import os

CHALLENGE_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.exe")
FLAG = "FLAG{carry_killers_quebram_a_difusao_linear}"

def main():
    print("========================================")
    print("  SPECTRUM-1024 Crypto Challenge Server")
    print("========================================")
    print()
    print("Bem-vindo ao oracle SPECTRUM-1024!")
    print()
    print("Opcoes:")
    print("  1. Cifrar mensagem (oracle)")
    print("  2. Decifrar mensagem (oracle)")
    print("  3. Verificar flag")
    print("  4. Sair")
    print()

    while True:
        try:
            choice = input("Escolha [1-4]: ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            pt = input("Plaintext (hex, max 256 chars): ").strip()
            key = input("Chave (hex, 64 chars): ").strip()
            try:
                result = subprocess.run(
                    [CHALLENGE_BIN, "encrypt", key, bytes.fromhex(pt).decode('latin-1')],
                    capture_output=True, text=True, timeout=5
                )
                print(result.stdout.strip())
            except Exception as e:
                print("Erro:", e)

        elif choice == "2":
            ct = input("Ciphertext (hex, 256 chars): ").strip()
            key = input("Chave (hex, 64 chars): ").strip()
            try:
                result = subprocess.run(
                    [CHALLENGE_BIN, "decrypt", key, ct],
                    capture_output=True, text=True, timeout=5
                )
                print(result.stdout.strip())
            except Exception as e:
                print("Erro:", e)

        elif choice == "3":
            flag = input("Flag: ").strip()
            if flag == FLAG:
                print("CORRETO! Parabens, voce completou o desafio!")
            else:
                print("Incorreto. Tente novamente.")

        elif choice == "4":
            print("Ate logo!")
            break
        else:
            print("Opcao invalida.")

if __name__ == "__main__":
    main()
