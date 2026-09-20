#!/usr/bin/env python3
"""
CifraTeste-1024 Challenge Server
Oracle de cifragem/decifragem para o desafio criptografico.
"""
import subprocess
import sys
import os

CHALLENGE_EXE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.exe")

def run_challenge(args):
    try:
        result = subprocess.run(
            [CHALLENGE_EXE] + args,
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception as e:
        return f"ERRO: {e}"

def main():
    print("=" * 50)
    print("  CIFRATESTE-1024 CHALLENGE SERVER")
    print("=" * 50)
    print()
    print("Comandos disponiveis:")
    print("  encrypt <plaintext_hex>  - Cifrar com chave publica (0)")
    print("  decrypt <ciphertext_hex> - Decifrar com chave publica (0)")
    print("  check <flag>             - Verificar flag")
    print("  help                     - Mostrar ajuda")
    print("  quit                     - Sair")
    print()

    while True:
        try:
            line = input("cifrateste> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAte logo!")
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        if cmd == "quit" or cmd == "exit":
            print("Ate logo!")
            break
        elif cmd == "help":
            print("Use: encrypt <hex>, decrypt <hex>, check <flag>")
        elif cmd == "encrypt" and len(parts) >= 2:
            pt_hex = parts[1]
            result = run_challenge(["encrypt", "0000000000000000000000000000000000000000000000000000000000000000", pt_hex])
            print(result)
        elif cmd == "decrypt" and len(parts) >= 2:
            ct_hex = parts[1]
            result = run_challenge(["decrypt", "0000000000000000000000000000000000000000000000000000000000000000", ct_hex])
            print(result)
        elif cmd == "check" and len(parts) >= 2:
            flag = " ".join(parts[1:])
            result = run_challenge(["check", flag])
            print(result)
        else:
            print("Comando invalido. Use 'help' para ajuda.")

if __name__ == "__main__":
    main()
