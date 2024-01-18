#include "pubg.h"
#include "memory.h"

template <typename T>
std::optional<pubg::Decryptor<T>> get_decryptor(const ZydisDecoder& decoder, uintptr_t start, uintptr_t end, location result) {
	static_assert(std::is_same<T, int32_t>::value | std::is_same<T, int64_t>::value, "Type error.");

	Analyser analyser(decoder, start, end, result);

	auto analysed = analyser.get_result();
	if (!analysed.has_value())
		return std::nullopt;

	auto& [instructions, read] = analysed.value();

	if (!std::holds_alternative<std::tuple<ZydisRegister, uint64_t, uint8_t>>(read))
		return std::nullopt;
	auto [reg, disp, size] = std::get<std::tuple<ZydisRegister, uint64_t, uint8_t>>(read);

	pubg::Decryptor<T> decryptor{};
	if (disp > std::numeric_limits<uint8_t>::max())
		return std::nullopt;
	decryptor.offset = (uint8_t)disp;

	int xor_count = 0;
	for (const auto& instruction : instructions) {
		const auto& mnemonic = instruction.instruction.mnemonic;
		const auto& operand = instruction.operands[1];
		switch (mnemonic)
		{
		case ZYDIS_MNEMONIC_XOR:
			if constexpr (std::is_same<T, int32_t>::value) {
				if (operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
					break;
				if (xor_count < 2)
					decryptor.xor_key[xor_count] = (int32_t)operand.imm.value.u;
				xor_count++;
			}
			break;
		case ZYDIS_MNEMONIC_MOV:
			if constexpr (std::is_same<T, int64_t>::value) {
				if (operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
					break;
				if (xor_count < 2)
					decryptor.xor_key[xor_count] = operand.imm.value.u;
				xor_count++;
			}
			break;
		case ZYDIS_MNEMONIC_ROR:
			decryptor.ror = true;
			[[fallthrough]];
		case ZYDIS_MNEMONIC_ROL:
			if (operand.imm.value.u > std::numeric_limits<uint8_t>::max())
				printf("ror/rol too big");
			decryptor.rval = (int8_t)operand.imm.value.u;
			break;
		case ZYDIS_MNEMONIC_SHR:
		case ZYDIS_MNEMONIC_SHL:
			if (operand.imm.value.u > std::numeric_limits<uint8_t>::max())
				printf("shr/shl too big");
			decryptor.sval = (int8_t)operand.imm.value.u;
			break;
		default:
			break;
		}
	}
	return decryptor;
}

std::optional<std::pair<pubg::Decryptor32, pubg::Decryptor32>> get_fname_decryptors(const ZydisDecoder& decoder, const uintptr_t start) {
	uintptr_t decryptor_result = find_instruction_category(decoder, start, start + 0x100, ZYDIS_CATEGORY_BINARY);
	if (!decryptor_result)
		return std::nullopt;

	const auto& result_val = Instruction(decoder, decryptor_result).operands[0].mem;

	auto index = get_decryptor<int32_t>(decoder, start, decryptor_result, std::tuple{ result_val.base, result_val.disp.value, 4 });
	auto number = get_decryptor<int32_t>(decoder, start, decryptor_result, std::tuple{ result_val.base, result_val.disp.value + 4, 4 });

	if (!index.has_value() || !number.has_value())
		return std::nullopt;

	return std::pair{ index.value(), number.value() };
}

std::optional<std::pair<pubg::Decryptor64, pubg::Decryptor64>> get_class_object_decryptors(const ZydisDecoder& decoder, uintptr_t start) {
	uintptr_t end = start;
	for (size_t i = 0; i < 3; i++)
		end = find_instruction_mnemonic(decoder, end + Instruction(decoder, end).instruction.length, start + 0x100, ZYDIS_MNEMONIC_XOR);
	if (!end)
		return std::nullopt;
	const auto& outer_result = Instruction(decoder, end).operands[0].reg.value;
	auto outer = get_decryptor<int64_t>(decoder, start, end, outer_result);

	start = end;
	for (size_t i = 0; i < 3; i++)
		end = find_instruction_mnemonic(decoder, end + Instruction(decoder, end).instruction.length, start + 0x100, ZYDIS_MNEMONIC_XOR);
	if (!end)
		return std::nullopt;
	const auto& class_result = Instruction(decoder, end).operands[0].reg.value;
	auto _class = get_decryptor<int64_t>(decoder, start, end, class_result);

	return std::pair{ _class.value(), outer.value() };
}

std::optional<pubg::Decryptor32> get_object_index_decryptor(const ZydisDecoder& decoder, uintptr_t start) {
	uintptr_t end = start;
	start = end;
	for (size_t i = 0; i < 3; i++)
		end = find_instruction_mnemonic(decoder, end + Instruction(decoder, end).instruction.length, start + 0x100, ZYDIS_MNEMONIC_XOR);
	if (!end)
		return std::nullopt;

	const auto& result_val = Instruction(decoder, end).operands[0].reg.value;
	return get_decryptor<int32_t>(decoder, start, end, result_val);
}

std::optional<pubg::decryptor_list> pubg::get_decryptors(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end) {
	// https://imgur.com/a/vd2KfNc
	// 4D 85 C0 0F 95 C0 84 C0 <--- the setnz stuff at the top
	// to find the decryptor
	uintptr_t offset = start;
	while (offset < end) { // try all signature matches
		uintptr_t decryptors_address = (uintptr_t)FindSignature((void*)offset, (void*)end, "4D 85 C0 0F 95 C0 84 C0");
		if (!decryptors_address)
			return std::nullopt;
		offset = decryptors_address + 8;

		decryptors_address = find_instruction_category(decoder, decryptors_address, decryptors_address + 0x100, ZYDIS_CATEGORY_COND_BR);
		if (!decryptors_address)
			continue;
		auto fname_decryptors = get_fname_decryptors(decoder, decryptors_address);

		Instruction instr(decoder, decryptors_address);
		uintptr_t class_decryptor_address = decryptors_address + instr.operands[0].imm.value.s + instr.instruction.length; // jmp address
		auto class_outer_decryptors = get_class_object_decryptors(decoder, class_decryptor_address);
		if (!fname_decryptors.has_value() || !class_outer_decryptors.has_value())
			continue;

		uintptr_t object_index_address = (uintptr_t)FindSignature((void*)start, (void*)end, "E8 ? ? ? ? 48 89 87 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 8B 40");
		if (!object_index_address)
			return std::nullopt;
		auto object_index_decryptor = get_object_index_decryptor(decoder, object_index_address);
		if (!object_index_decryptor.has_value())
			return std::nullopt;

		//fname_decryptors->first.print();
		//fname_decryptors->second.print();
		//class_outer_decryptors->second.print();
		//class_outer_decryptors->second.print();

		return pubg::decryptor_list{
			std::make_unique<pubg::Decryptor32>(fname_decryptors->first),
			std::make_unique<pubg::Decryptor32>(fname_decryptors->second),
			std::make_unique<pubg::Decryptor32>(object_index_decryptor.value()),
			std::make_unique<pubg::Decryptor64>(class_outer_decryptors->first),
			std::make_unique<pubg::Decryptor64>(class_outer_decryptors->second),
		};
	}
	return std::nullopt;
}
