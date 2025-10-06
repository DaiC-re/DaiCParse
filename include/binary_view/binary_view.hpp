#pragma once

#include "binary/binary.hpp"

class BinaryView {
   public:
	BinaryView(const std::unique_ptr<Binary> &binary);
	~BinaryView() = default;
	std::vector<uint8_t> getSectionContentFromAddr(
		size_t addr, size_t content_size);
	std::string viewHexChunk(
		size_t addr);

   private:
	const std::unique_ptr<Binary> &_binary;
    LIEF::Section *_last_section = nullptr;
};
