#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstdint>
#include <iostream>
#pragma comment(lib, "bcrypt.lib")

// AES-256-ECB decryption using Windows BCrypt API
// Returns decrypted bytes, or empty vector on failure
std::vector<uint8_t> AESDecrypt(const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> plaintext;

    if (ciphertext.empty() || key.empty()) {
        std::cerr << "[-] AESDecrypt: ciphertext or key is empty.\n";
        return plaintext;
    }
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        std::cerr << "[-] AESDecrypt: key must be 16, 24, or 32 bytes.\n";
        return plaintext;
    }
    if (ciphertext.size() % 16 != 0) {
        std::cerr << "[-] AESDecrypt: ciphertext size must be a multiple of 16.\n";
        return plaintext;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) {
        std::cerr << "[-] BCryptOpenAlgorithmProvider failed: 0x" << std::hex << status << "\n";
        return plaintext;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != 0) {
        std::cerr << "[-] BCryptSetProperty failed: 0x" << std::hex << status << "\n";
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plaintext;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (status != 0) {
        std::cerr << "[-] BCryptGenerateSymmetricKey failed: 0x" << std::hex << status << "\n";
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plaintext;
    }

    // Step 1: query required output size
    ULONG requiredSize = 0;
    status = BCryptDecrypt(hKey,
        (PUCHAR)ciphertext.data(), static_cast<ULONG>(ciphertext.size()),
        NULL, NULL, 0, NULL, 0, &requiredSize, 0);
    if (status != 0) {
        std::cerr << "[-] BCryptDecrypt (size query) failed: 0x" << std::hex << status << "\n";
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plaintext;
    }

    // Step 2: perform decryption
    plaintext.resize(requiredSize);
    ULONG cbResult = requiredSize;
    status = BCryptDecrypt(hKey,
        (PUCHAR)ciphertext.data(), static_cast<ULONG>(ciphertext.size()),
        NULL, NULL, 0,
        plaintext.data(), cbResult, &cbResult, 0);
    if (status != 0) {
        std::cerr << "[-] BCryptDecrypt failed: 0x" << std::hex << status << "\n";
        plaintext.clear();
    }
    else {
        plaintext.resize(cbResult);
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return plaintext;
}