#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstdint>
#include <iostream>
#pragma comment(lib, "bcrypt.lib")

// Pad data to AES block size using PKCS#7
static std::vector<uint8_t> PadToBlockSize(const std::vector<uint8_t>& data, size_t blockSize)
{
    std::vector<uint8_t> padded = data;
    size_t padding = blockSize - (data.size() % blockSize);
    padded.insert(padded.end(), padding, static_cast<uint8_t>(padding));
    return padded;
}

// AES-256-ECB encryption using Windows BCrypt API
// Returns encrypted bytes, or empty vector on failure
std::vector<uint8_t> AESEncrypt(const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> ciphertext;

    if (plaintext.empty() || key.empty()) {
        std::cerr << "[-] AESEncrypt: plaintext or key is empty.\n";
        return ciphertext;
    }
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        std::cerr << "[-] AESEncrypt: key must be 16, 24, or 32 bytes.\n";
        return ciphertext;
    }

    std::vector<uint8_t> padded = PadToBlockSize(plaintext, 16);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) {
        std::cerr << "[-] BCryptOpenAlgorithmProvider failed: 0x" << std::hex << status << "\n";
        return ciphertext;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != 0) {
        std::cerr << "[-] BCryptSetProperty failed: 0x" << std::hex << status << "\n";
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ciphertext;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (status != 0) {
        std::cerr << "[-] BCryptGenerateSymmetricKey failed: 0x" << std::hex << status << "\n";
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ciphertext;
    }

    // Step 1: query required output size
    ULONG requiredSize = 0;
    status = BCryptEncrypt(hKey,
        (PUCHAR)padded.data(), static_cast<ULONG>(padded.size()),
        NULL, NULL, 0, NULL, 0, &requiredSize, 0);
    if (status != 0) {
        std::cerr << "[-] BCryptEncrypt (size query) failed: 0x" << std::hex << status << "\n";
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ciphertext;
    }

    // Step 2: perform encryption
    ciphertext.resize(requiredSize);
    ULONG cbResult = requiredSize;
    status = BCryptEncrypt(hKey,
        (PUCHAR)padded.data(), static_cast<ULONG>(padded.size()),
        NULL, NULL, 0,
        ciphertext.data(), cbResult, &cbResult, 0);
    if (status != 0) {
        std::cerr << "[-] BCryptEncrypt failed: 0x" << std::hex << status << "\n";
        ciphertext.clear();
    }
    else {
        ciphertext.resize(cbResult);
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ciphertext;
}