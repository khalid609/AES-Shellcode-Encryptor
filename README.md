# 🔒 AES Shellcode Encryptor

> **⚠️ FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**

---

## 📌 Overview

A standalone C++ tool that AES-256-ECB encrypts a raw shellcode byte array and outputs two ready-to-use `.h` header files — the encrypted shellcode and the key — designed to be dropped directly into a shellcode injector project.

---

## 📁 Project Structure

```
AES-Shellcode-Encryptor/
├── main.cpp                  ← entry point
├── AESEncrypt.h              ← AES-256-ECB encryption (BCrypt API)
├── AESDecrypt.h              ← AES-256-ECB decryption (BCrypt API)
├── shellcode.h               ← INPUT: paste your raw shellcode here
├── encrypted_shellcode.h     ← OUTPUT: auto-generated
└── key.h                     ← OUTPUT: auto-generated
```

---

## 🔬 How It Works

```
shellcode.h  (raw bytes you provide)
      │
      ▼
AESEncrypt()  →  PKCS#7 pad  →  BCrypt AES-256-ECB
      │
      ├──→  encrypted_shellcode.h   (shellcode[] array)
      └──→  key.h                   (aesKey[] array)
```

Copy both output files into your injector project — they map directly to `demon.x64.h`.

---

## 🚀 How to Use

### Step 1 — Add your shellcode

Open `shellcode.h` and paste your raw shellcode bytes:

```cpp
std::vector<uint8_t> shellcode = {
    0xFC, 0x48, 0x83, ...
};
```

### Step 2 — Set your AES key

Open `main.cpp` and replace the default key with your own 32-byte key:

```cpp
std::vector<uint8_t> key = {
    0x00, 0x01, ...   // 32 bytes for AES-256
};
```

> Supported key sizes: **16 bytes** (AES-128), **24 bytes** (AES-192), **32 bytes** (AES-256)

### Step 3 — Build

**Visual Studio:**
```
Build → Build Solution  (Ctrl+Shift+B)
Platform Target: x64
```

**g++:**
```bash
g++ main.cpp -o Encryptor -lbcrypt
```

### Step 4 — Run

```cmd
Encryptor.exe
```

**Expected output:**
```
[*] Shellcode size : 256 bytes
[+] Encrypted size : 256 bytes
[+] Written to encrypted_shellcode.h
[+] Written to key.h
[+] Done — copy encrypted_shellcode.h and key.h to your injector.
```

### Step 5 — Copy output to injector

Copy both generated files into your APC Injector project:

```
encrypted_shellcode.h  →  injector/demon.x64.h
key.h                  →  injector/demon.x64.h   (merge both arrays)
```

---

## 👤 Author

**Khalid** — Cybersecurity Student
GitHub: [@khalid609](https://github.com/khalid609)

---

## 📄 License

For educational and authorized security research use only.
