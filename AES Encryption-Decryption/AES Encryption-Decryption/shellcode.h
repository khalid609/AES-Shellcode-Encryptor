#pragma once
#include <vector>
#include <cstdint>

// ── INPUT ────────────────────────────────────────────────────────────────────
// Paste your raw shellcode bytes here before running the encryptor.
// 
// Example: msfvenom -p windows/x64/exec CMD=calc.exe -f raw | xxd -i

std::vector<uint8_t> shellcode = {
    // add your shellcode bytes here
};