# 🔐 AES Utils — Quantum Secure Messaging System (QSMS)

## 📘 Overview
`aes_utils.py` is a Python utility module for **AES-GCM encryption and decryption**.  
It’s a part of the **Quantum Secure Messaging System (QSMS)** project — providing secure message encryption using AES-GCM with keys derived from quantum-safe secrets (like Kyber KEM output).

This script also includes a built-in **self-test** to verify that the encryption and decryption processes work correctly.

---

## 🧩 Features
- AES-GCM encryption & decryption  
- Key derivation using HKDF (HMAC-based Key Derivation Function)  
- Support for Additional Authenticated Data (AAD)  
- Secure random nonce generation  
- Built-in self-test mode for verification  
- Easy to integrate with larger systems like QSMS  

---

## 🛠️ Installation Guide

### 1️⃣ Clone or Download the Project
```bash
git clone https://github.com/<your-username>/Quantum-SMS.git
cd Quantum-SMS
```
### 2️⃣ Create a Virtual Environment
```bash
python -m venv .venv
```

### 4️⃣ Upgrade pip
```bash
python -m pip install --upgrade pip
```

### 5️⃣ Install Dependencies
```bash
pip install cryptography
```

### ▶️ Run Self-Test
```bash
python aes_utils.py

```

### Expected Output:
``` swift
Running aes_utils self-test...
Derived key (base64): <some-key>
Nonce (b64): <some-nonce>
Ciphertext+Tag (b64): <some-cipher>
Self-test passed — plaintext successfully recovered.
```