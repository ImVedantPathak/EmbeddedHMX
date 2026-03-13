#!/usr/bin/env python3
"""
vault.py - Folder Encryptor / Decryptor

Encrypts ALL file contents and completely hides the folder structure.
Everything is moved into a hidden .vault_data/ directory with random names.
Decrypt with the same password to restore everything exactly as it was.

Usage:
    python vault.py encrypt <folder>
    python vault.py decrypt <folder>

Requirements:
    pip install cryptography
"""

import os
import sys
import json
import base64
import secrets
import getpass
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

VAULT_MANIFEST = ".vault"
VAULT_DATA_DIR = ".vault_data"
SKIP_FILES = {"vault.py", "requirements.txt", ".gitignore", "INSTRUCTIONS.md"}


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit Fernet key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_folder(folder_path: str, password: str) -> None:
    root = Path(folder_path).resolve()
    vault_file = root / VAULT_MANIFEST
    vault_data = root / VAULT_DATA_DIR

    if vault_file.exists():
        print("[!] This folder is already encrypted.")
        sys.exit(1)

    # Generate a random 16-byte salt and derive the encryption key
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    SKIP_DIRS = {VAULT_DATA_DIR, "venv", ".git"}

    # Collect all files (skip vault dir, venv, .git)
    all_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname in SKIP_FILES:
                continue
            fpath = Path(dirpath) / fname
            rel = str(fpath.relative_to(root))
            all_files.append((fpath, rel))

    if not all_files:
        print("[!] No files found to encrypt.")
        sys.exit(1)

    vault_data.mkdir(exist_ok=True)

    # Encrypt each file and store it with a random hex name inside .vault_data/
    manifest = {}   # { random_hex_name : original_relative_path }
    for fpath, rel_path in all_files:
        random_name = secrets.token_hex(16)
        with open(fpath, "rb") as f:
            plaintext = f.read()
        ciphertext = fernet.encrypt(plaintext)
        with open(vault_data / random_name, "wb") as f:
            f.write(ciphertext)
        manifest[random_name] = rel_path
        fpath.unlink()  # remove original file

    # Remove now-empty subdirectories (bottom-up)
    for dirpath, _, _ in os.walk(root, topdown=False):
        p = Path(dirpath)
        if p in (root, vault_data):
            continue
        try:
            p.rmdir()   # only succeeds if directory is empty
        except OSError:
            pass

    # Encrypt the manifest and write: salt (16 bytes) + encrypted manifest
    manifest_bytes = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    encrypted_manifest = fernet.encrypt(manifest_bytes)
    with open(vault_file, "wb") as f:
        f.write(salt + encrypted_manifest)

    print(f"[+] Encrypted {len(manifest)} file(s). Folder is now locked.")


def decrypt_folder(folder_path: str, password: str) -> None:
    root = Path(folder_path).resolve()
    vault_file = root / VAULT_MANIFEST
    vault_data = root / VAULT_DATA_DIR

    if not vault_file.exists():
        print("[!] No .vault file found — this folder is not encrypted.")
        sys.exit(1)

    # Read salt (first 16 bytes) + encrypted manifest (rest)
    with open(vault_file, "rb") as f:
        raw = f.read()
    salt = raw[:16]
    encrypted_manifest = raw[16:]

    # Derive the key and attempt to decrypt the manifest
    key = derive_key(password, salt)
    fernet = Fernet(key)
    try:
        manifest_bytes = fernet.decrypt(encrypted_manifest)
    except InvalidToken:
        print("[!] Wrong password or corrupted vault file.")
        sys.exit(1)

    manifest = json.loads(manifest_bytes.decode("utf-8"))

    # Restore each file to its original path
    failed = 0
    for random_name, rel_path in manifest.items():
        enc_file = vault_data / random_name
        if not enc_file.exists():
            print(f"[!] Missing encrypted blob: {random_name}  (original: {rel_path})")
            failed += 1
            continue
        with open(enc_file, "rb") as f:
            ciphertext = f.read()
        try:
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken:
            print(f"[!] Could not decrypt: {rel_path}")
            failed += 1
            continue
        dest = root / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(plaintext)
        enc_file.unlink()

    # Clean up vault artifacts only if fully successful
    if failed == 0:
        try:
            vault_data.rmdir()
        except OSError:
            pass
        vault_file.unlink()
        print(f"[+] Decrypted {len(manifest)} file(s). Folder is fully restored.")
    else:
        print(f"[!] Decryption completed with {failed} error(s). Vault files kept.")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("encrypt", "decrypt"):
        print("Usage:  python vault.py <encrypt|decrypt> <folder>")
        print()
        print("  encrypt   Lock the folder — encrypts all files, hides structure")
        print("  decrypt   Unlock the folder — restores everything with the password")
        sys.exit(1)

    mode   = sys.argv[1]
    folder = sys.argv[2]

    if not Path(folder).is_dir():
        print(f"[!] '{folder}' is not a valid directory.")
        sys.exit(1)

    password = getpass.getpass("Password: ")
    if not password:
        print("[!] Password cannot be empty.")
        sys.exit(1)

    if mode == "encrypt":
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[!] Passwords do not match.")
            sys.exit(1)
        encrypt_folder(folder, password)
    else:
        decrypt_folder(folder, password)


if __name__ == "__main__":
    main()
