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

	if (fname_index->is_valid())
		std::cout << "FName index:\n" << std::string(*fname_index) << "\n";
	if (fname_number->is_valid())
		std::cout << "FName number:\n" << std::string(*fname_number) << "\n";
	if (object_index->is_valid())
		std::cout << "Object index:\n" << std::string(*object_index) << "\n";
	if (object_class->is_valid())
		std::cout << "Object class:\n" << std::string(*object_class) << "\n";
	if (object_outer->is_valid())
		std::cout << "Object outer:\n" << std::string(*object_outer) << "\n";
}