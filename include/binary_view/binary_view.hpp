#pragma once

#include "binary/binary.hpp"

class BinaryView {
   public:
	BinaryView(const std::unique_ptr<Binary> &binary);
	~BinaryView() = default;
	std::vector<uint8_t> getSectionContentFromAddr(
		size_t addr, size_t content_size) const;
	std::string viewHexChunk(
		size_t addr) const;

   private:
	const std::unique_ptr<Binary> &_binary;
};
