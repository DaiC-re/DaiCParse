#include "binary_view/binary_view.hpp"
#include "hex_utils/hex_utils.hpp"
#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/Section.hpp>

constexpr size_t CHUNK_SIZE = 0x1000;

BinaryView::BinaryView(const std::unique_ptr<Binary> &binary)
    : _binary(binary) {}

//size_t BinaryView::getLineCount() const {
//	return 0;
//}

std::vector<uint8_t> BinaryView::getSectionContentFromAddr(size_t addr, size_t content_size = CHUNK_SIZE) const {
    if (LIEF::PE::Binary::classof(_binary->_lief_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary->_lief_binary);

        LIEF::PE::Section *section = pe.section_from_rva(addr);
        std::cout << std::format(
            "addr: {:#x}, section: {}\n", addr,
            section != nullptr ? section->name() : "nullptr");
        if (section == nullptr) {
            throw std::runtime_error("No section found at this address, dev error");
        }
        std::array<LIEF::span<const uint8_t>, 2> contents = {
            section->content(), section->padding()};
        auto start_offset = addr - section->virtual_address();
        auto range = contents | std::views::join | std::views::drop(start_offset) | std::views::take(content_size);
        return std::ranges::to<std::vector>(range);
    } else {
		throw std::runtime_error("Binary format not supported");
    }
    return {};
}

std::string BinaryView::viewHexChunk(size_t index) const {
    auto addr = index * 0x10 + 0x1000;
    auto span = _binary->_lief_binary->get_content_from_virtual_address(addr, CHUNK_SIZE);
    std::vector<uint8_t> content = getSectionContentFromAddr(addr);
    return contentToHex(addr, content);
}
