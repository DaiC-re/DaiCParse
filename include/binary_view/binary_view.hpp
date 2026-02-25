#pragma once

#include "binary/binary.hpp"
#include <ranges>

struct CheckPoint {
	size_t index;
	uintptr_t addr;
};

class BinaryView {
public:
	BinaryView(Binary* binary);
	~BinaryView() = default;
	std::vector<uint8_t> getSectionContentFromAddr(
		size_t addr, size_t content_size);
	std::string viewHexChunk(
		size_t addr);
	std::string viewDisasmChunk(
		size_t addr);
	BinSection* getSectionAtAddr(uintptr_t virtual_addr);
	BinSection* getNextSection(BinSection* section);

private:
	std::pair<uintptr_t, CheckPoint> getDisasmInstructionAddr(size_t index);

private:
	Binary* _binary;
	uintptr_t _relative_text_addr = 0x1000;
};
