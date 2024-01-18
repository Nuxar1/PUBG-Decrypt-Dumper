#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>

#include "pubg.h"

std::vector<uint8_t> open_binary_file(std::filesystem::path path) {
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open()) {
		std::cout << "Failed to open file: " << path << std::endl;
		return {};
	}

	file.seekg(0, std::ios::end);
	size_t size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<uint8_t> data(size);
	file.read((char*)data.data(), size);
	return data;
}

int main(int argc, char** argv)
{
	if (argc != 2) {
		std::cout << "Usage: " << argv[0] << " <path to TslGame.exe dump>" << std::endl;
		return 1;
	}
	std::vector<uint8_t> data = open_binary_file(argv[1]);

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	auto result = pubg::get_decryptors(decoder, (uintptr_t)data.data(), (uintptr_t)data.data() + data.size());

	if (!result.has_value()) {
		std::cout << "Failed to find decryptors" << std::endl;
		return 1;
	}

	const pubg::decryptor_list& decryptors = result.value();

	std::cout << "Found decryptors:" << std::endl;

	auto& [fname_index, fname_number, object_index, object_class, object_outer] = decryptors;

	if (fname_index->is_valid() && fname_number->is_valid()) {
		std::cout << "FName index decryptor:" << std::endl;
		std::cout << "ROR: " << (fname_index->ror ? "true" : "false") << std::endl;
		std::cout << "XOR key: " << std::hex << fname_index->xor_key[0] << ", " << fname_index->xor_key[1] << std::endl;
		std::cout << "ROR value: " << std::dec << (int)fname_index->rval << std::endl;
		std::cout << "SHR/SHL value: " << (int)fname_index->sval << std::endl;
		std::cout << "Offset: " << (int)fname_index->offset << std::endl;
		std::cout << std::endl;

		std::cout << "FName number decryptor:" << std::endl;
		std::cout << "ROR: " << (fname_number->ror ? "true" : "false") << std::endl;
		std::cout << "XOR key: " << std::hex << fname_number->xor_key[0] << ", " << fname_number->xor_key[1] << std::endl;
		std::cout << "ROR value: " << std::dec << (int)fname_number->rval << std::endl;
		std::cout << "SHR/SHL value: " << (int)fname_number->sval << std::endl;
		std::cout << "Offset: " << (int)fname_number->offset << std::endl;
		std::cout << std::endl;
	}

	if (object_index->is_valid() && object_class->is_valid() && object_outer->is_valid()) {
		std::cout << "Object index decryptor:" << std::endl;
		std::cout << "ROR: " << (object_index->ror ? "true" : "false") << std::endl;
		std::cout << "XOR key: " << std::hex << object_index->xor_key[0] << ", " << object_index->xor_key[1] << std::endl;
		std::cout << "ROR value: " << std::dec << (int)object_index->rval << std::endl;
		std::cout << "SHR/SHL value: " << (int)object_index->sval << std::endl;
		std::cout << "Offset: " << (int)object_index->offset << std::endl;
		std::cout << std::endl;

		std::cout << "Object class decryptor:" << std::endl;
		std::cout << "ROR: " << (object_class->ror ? "true" : "false") << std::endl;
		std::cout << "XOR key: " << std::hex << object_class->xor_key[0] << ", " << object_class->xor_key[1] << std::endl;
		std::cout << "ROR value: " << std::dec << (int)object_class->rval << std::endl;
		std::cout << "SHR/SHL value: " << (int)object_class->sval << std::endl;
		std::cout << "Offset: " << (int)object_class->offset << std::endl;
		std::cout << std::endl;

		std::cout << "Object outer decryptor:" << std::endl;
		std::cout << "ROR: " << (object_outer->ror ? "true" : "false") << std::endl;
		std::cout << "XOR key: " << std::hex << object_outer->xor_key[0] << ", " << object_outer->xor_key[1] << std::endl;
		std::cout << "ROR value: " << std::dec << (int)object_outer->rval << std::endl;
		std::cout << "SHR/SHL value: " << (int)object_outer->sval << std::endl;
		std::cout << "Offset: " << (int)object_outer->offset << std::endl;
		std::cout << std::endl;
	}
}