#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstdint>
#include "AESEncrypt.h"
#include "shellcode.h"

// ── Output writer ─────────────────────────────────────────────────────────────
// Writes a byte vector to a .h file as a std::vector<uint8_t> declaration
void WriteToHeaderFile(const std::string& filename,
    const std::string& varName,
    const std::vector<uint8_t>& data)
{
    std::ofstream out(filename);
    if (!out) {
        std::cerr << "[-] Could not open " << filename << " for writing.\n";
        return;
    }

    out << "#pragma once\n";
    out << "#include <vector>\n";
    out << "#include <cstdint>\n\n";
    out << "std::vector<uint8_t> " << varName << " = {\n    ";

    for (size_t i = 0; i < data.size(); ++i) {
        out << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i != data.size() - 1) out << ", ";
        if ((i + 1) % 12 == 0) out << "\n    ";
    }

    out << "\n};\n";
    out.close();
    std::cout << "[+] Written to " << filename << "\n";
}

// ── Entry point ───────────────────────────────────────────────────────────────
int main()
{
    // ── AES-256 key — replace with your own 32-byte key ──────────────────────
    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    // ── Validate shellcode ────────────────────────────────────────────────────
    if (shellcode.empty()) {
        std::cerr << "[-] shellcode.h is empty — add your shellcode bytes first.\n";
        return 1;
    }

    std::cout << "[*] Shellcode size : " << std::dec << shellcode.size() << " bytes\n";

    // ── Encrypt ───────────────────────────────────────────────────────────────
    std::vector<uint8_t> encrypted = AESEncrypt(shellcode, key);
    if (encrypted.empty()) {
        std::cerr << "[-] Encryption failed.\n";
        return 1;
    }

    std::cout << "[+] Encrypted size : " << encrypted.size() << " bytes\n";

    // ── Write output headers ──────────────────────────────────────────────────
    WriteToHeaderFile("encrypted_shellcode.h", "shellcode", encrypted);
    WriteToHeaderFile("key.h", "aesKey", key);

    std::cout << "[+] Done — copy encrypted_shellcode.h and key.h to your injector.\n";
    return 0;
}