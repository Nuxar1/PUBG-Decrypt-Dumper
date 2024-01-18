#pragma once
#include <functional>
#define ZYDIS_STATIC_BUILD
#include <Zydis/Zydis.h>
#pragma comment(lib, "Zydis.lib")

uint8_t* FindSignature(void* start, void* end, const char* sig, const char* pat);
uint8_t* FindSignature(void* start, void* end, const char* ida_sig);


uint64_t find_instruction_category(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end, const ZydisInstructionCategory category);

uint64_t find_instruction_mnemonic(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end, const ZydisMnemonic mnemonic);