#include "analyser.h"
#include <string>

bool Analyser::is_same_location(const location& a, const location& b) const {
	if (a.index() != b.index())
		return false;

	if (std::holds_alternative<ZydisRegister>(a))
		return std::get<ZydisRegister>(a) == std::get<ZydisRegister>(b);
	else {
		auto a_tuple = std::get<std::tuple<ZydisRegister, uint64_t, uint8_t>>(a);
		auto b_tuple = std::get<std::tuple<ZydisRegister, uint64_t, uint8_t>>(b);

		// same register
		if (std::get<0>(a_tuple) != std::get<0>(b_tuple))
			return false;

		// overlapping memory
		// a_base + a_size > b_base && b_base + b_size > a_base
		if (std::get<1>(a_tuple) + std::get<2>(a_tuple) > std::get<1>(b_tuple)
			&& std::get<1>(b_tuple) + std::get<2>(b_tuple) > std::get<1>(a_tuple))
			return true;
		else
			return false;
	}
}

void Analyser::mark_needed_instructions(size_t current_instruction) {
	auto& instruction = instructions[current_instruction];
	if (instruction.needed)
		return;
	instruction.needed = true;

	for (size_t i = 0; i < instruction.instruction.operand_count_visible; i++) {
		auto& operand = instruction.operands[i];

		// recursive call read operands
		if ((operand.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) {
			if (auto loc = get_location(operand)) {
				auto last_modified = get_last_modified(instruction, loc.value());
				if (!last_modified.has_value()
					|| (last_modified.value() == current_instruction && current_instruction == 0)) {
					unknown_values.push_back(loc.value());
					instruction.unknown_value = true; // just for debugging purposes (print the instruction)
				}
				else if (last_modified.value() == current_instruction) {
					auto prev_last_modified = get_last_modified(instructions[current_instruction - 1], loc.value());
					if (prev_last_modified.has_value())
						mark_needed_instructions(prev_last_modified.value());
				}
				else
					mark_needed_instructions(last_modified.value());
			}
		}
	}
}

std::optional<location> Analyser::get_location(const ZydisDecodedOperand& operand) const {
	if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER)
		return operand.reg.value;
	else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
		return std::make_tuple(operand.mem.base, operand.mem.disp.value, (uint8_t)(operand.size / 8u));
	else
		return std::nullopt;
}

std::optional<size_t> Analyser::get_last_modified(const InstructionTrace& instruction, const location& location) const {
	auto it = instruction.last_modified.find(location); // fast path
	if (it != instruction.last_modified.end())
		return it->second;

	for (const auto& [loc, last_modified] : instruction.last_modified) // slow path (overlapping memory)
	{
		if (is_same_location(loc, location))
			return last_modified;
	}

	return std::nullopt;
}


bool Analyser::init()
{
	if (std::holds_alternative<ZydisRegister>(result))
		printf("Analyzing %s\n", ZydisRegisterGetString(std::get<ZydisRegister>(result)));
	else {
		auto [base, disp, size] = std::get<std::tuple<ZydisRegister, uint64_t, uint8_t>>(result);
		std::string str = "Analyzing [" + std::string(ZydisRegisterGetString(base)) + " + " + std::to_string(disp) + "]" + " (" + std::to_string(size) + " bytes)";
		printf("%s\n", str.c_str());
	}

	uintptr_t current = start;
	while (current <= end) {
		InstructionTrace instruction = {};
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)current, INT_MAX, &instruction.instruction, instruction.operands)))
			break;

		instruction.address = current;
		if (instructions.size() > 0)
			instruction.last_modified = instructions.back().last_modified;
		else
			instruction.last_modified = {};

		const size_t current_instruction = instructions.size();
		for (size_t i = 0; i < instruction.instruction.operand_count_visible; i++) {
			auto& operand = instruction.operands[i];
			if (!(operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
				continue;

			auto loc = get_location(operand);
			if (!loc.has_value())
				continue;

			instruction.last_modified[loc.value()] = current_instruction;
		}

		current += instruction.instruction.length;
		instructions.push_back(instruction);
	}

	auto loc = get_last_modified(instructions.back(), result);
	if (!loc.has_value())
		return false;

	mark_needed_instructions(loc.value());
	return true;
}

std::optional<std::pair<std::vector<InstructionTrace>, location>> Analyser::get_result() const {
	std::vector<InstructionTrace> needed;
	for (const auto& instruction : instructions) {

		ZydisFormatter formatter;
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction.instruction, instruction.operands, instruction.instruction.operand_count, buffer, sizeof(buffer), 0, 0);

		// print needed green, unknown red, rest white
		if (instruction.unknown_value)
			printf("\033[0;31m");
		else if (instruction.needed)
			printf("\033[0;32m");
		else
			printf("\033[0m");
		printf("%s\n", buffer);

		if (instruction.needed)
			needed.push_back(instruction);
	}
	printf("\033[0m");

	if (unknown_values.size() == 0)
		return std::nullopt;

	location loc = unknown_values.front();
	if (unknown_values.size() > 1) {
		// make sure unknown instructions contain the same location
		for (const auto& l : unknown_values) {
			if (!is_same_location(l, loc)) {
				printf("Error: unknown values contain different locations\n\n");
				return std::nullopt;
			}
		}
	}

	printf("\n");

	return std::pair{ needed, loc };
}
