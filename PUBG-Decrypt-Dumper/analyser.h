#pragma once
#include <variant>
#include "utils.h"
#include <map>
#include <optional>
#define ZYDIS_STATIC_BUILD
#include <Zydis/Zydis.h>
#pragma comment(lib, "Zydis.lib")

// Register, [Register (base), Offset, Size]
// todo multiple registers could be the base
using location = std::variant<
	ZydisRegister,
	std::tuple<ZydisRegister, uint64_t, uint8_t>
>;

struct Instruction {
	uintptr_t address;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	Instruction() = default;
	Instruction(const ZydisDecoder& decoder, uintptr_t address) {
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)address, 0x100, &instruction, operands)))
			throw std::exception("Failed to decode instruction");
		this->address = address;
		for (size_t i = 0; i < ZYDIS_MAX_OPERAND_COUNT; i++)
			this->operands[i] = operands[i];
	}
};

struct InstructionTrace : public Instruction {
	bool needed;
	bool unknown_value;

	// Location, Index in the instruction list
	std::map<location, size_t> last_modified;
};
class Analyser {
	Analyser() = delete;

	bool is_same_location(const location& a, const location& b) const;
	void mark_needed_instructions(size_t current_instruction);
	std::optional<location> get_location(const ZydisDecodedOperand& operand) const;
	std::optional<size_t> get_last_modified(const InstructionTrace& instruction, const location& location) const;
public:
	/**
	* @brief Analyse the given data and find all instructions needed for the result
	*
	* @param start The start of the data to analyse
	* @param end The end of the data to analyse (the last instruction, not the end of the data)
	* @param result The location of the result
	*
	*/
	Analyser(const ZydisDecoder& decoder, uintptr_t start, uintptr_t end, location result) : decoder(decoder), start(start), end(end), result(result) {}

	bool init();

	std::optional<std::pair<std::vector<InstructionTrace>, location>> get_result() const;
private:
	// Needed instructions, Unknown value instructions
	std::vector<InstructionTrace> instructions;

	// filled in by "mark_needed_instructions"
	std::vector<location> unknown_values;

	const ZydisDecoder& decoder;
	const uintptr_t start;
	const uintptr_t end;
	const location result;
};