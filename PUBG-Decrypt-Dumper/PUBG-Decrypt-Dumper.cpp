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
}