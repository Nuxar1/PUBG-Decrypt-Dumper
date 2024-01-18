#include <windows.h>
#include <winternl.h>
#include "memory.h"
#include "utils.h"

bool Compare(const uint8_t* data, const uint8_t* sig, const char* pat, uint32_t size) {
	for (uint32_t i = 0; i < size; i++) {
		if (data[i] != sig[i] && pat[i] != '?') {
			return false;
		}
	}
	return true;
}

uint8_t* FindSignature(void* start, void* end, const char* sig, const char* pat) {
	uint32_t size = strnlen_s(pat, 0x100);
	for (uint8_t* it = (uint8_t*)start; it < (uint8_t*)end - size; it++) {
		if (Compare(it, (uint8_t*)sig, pat, size)) {
			return it;
		};
	}
	return 0;
}

uint8_t* FindSignature(void* start, void* end, const char* ida_sig) {
	// ida sig has format: "00 ? 00" or "00 ?? 00"
	// each word is 2 bytes sperated by space
	// ? == ?? == any byte
	size_t ida_len = strnlen_s(ida_sig, 0x100);
	const char* current = ida_sig;
	// max size is 0x100
	size_t current_size = 0;
	char sig[0x100];
	char pat[0x100];
	while (current < ida_sig + ida_len) {
		if (*current == ' ')
			current++; // skip space
		else if (*current == '?') {
			sig[current_size] = 0;
			pat[current_size] = '?';
			current_size++;

			current++;
			if (*current == '?')
				current++;
		} else {
			uint8_t byte = (uint8_t)strtoul(current, nullptr, 16);
			sig[current_size] = byte;
			pat[current_size] = 'x';
			current_size++;

			current += 2; // skip byte
		}
	}
	sig[current_size] = 0;
	pat[current_size] = 0;
	return FindSignature(start, end, sig, pat);
}

uint64_t find_instuction(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end, const std::function<bool(const ZydisDecodedInstruction&)>& callback) {
	ZydisDecodedInstruction instruction;
	ZydisDecoderContext context;
	uintptr_t offset = start;
	while (offset < end) {
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, &context, (const void*)offset, end - offset, &instruction)))
			break;

		if (callback(instruction))
			return offset;
		offset += instruction.length;
	}
	return 0;
}


uint64_t find_instruction_category(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end, const ZydisInstructionCategory category) {
	return find_instuction(decoder, start, end, [&](const ZydisDecodedInstruction& instruction)->bool {
		return instruction.meta.category == category;
		});
}

uintptr_t find_instruction_mnemonic(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end, const ZydisMnemonic mnemonic) {
	return find_instuction(decoder, start, end, [&](const ZydisDecodedInstruction& instruction)->bool {
		return instruction.mnemonic == mnemonic;
		});
}