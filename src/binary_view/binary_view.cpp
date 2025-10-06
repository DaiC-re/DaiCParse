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
std::vector<uint8_t> BinaryView::getSectionContentFromAddr(size_t addr, size_t content_size = CHUNK_SIZE) {
    if (LIEF::PE::Binary::classof(_binary->_lief_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary->_lief_binary);

        LIEF::PE::Section *section = pe.section_from_rva(addr);
        std::cout << std::format(
            "addr: {:#x}, section: {}\n", addr,
            section != nullptr ? section->name() : "nullptr");
        if (section == nullptr) {
            //throw std::runtime_error("No section found at this address, dev error");
            std::cerr << "No section found at this address, dev error\n";
            section = static_cast<LIEF::PE::Section *>(_last_section);
        }
        _last_section = section;
        std::array<LIEF::span<const uint8_t>, 2> contents = {
            section->content(), section->padding()};
        auto start_offset = addr - section->virtual_address();
        auto i = 0;
        for (auto &c : section->padding()) {
            std::cout << section->padding().size_bytes() << "\n";
            std::cout << std::format("{:02x} ", c);
            ++i;
        }
        std::cout << "index: " << i
                  << ", padding size: " << section->padding().size_bytes()
                  << "\n";
        std::cout << std::format(
            "section: {}, virtual_address: {:#x}, size_of_raw_data: {:#x}, sizeof_raw_data: {:#x}, padding size: {:#x}\n",
            section->name(), section->virtual_address(),
            section->sizeof_raw_data(), section->sizeof_raw_data(),
            section->padding().size());
        std::cout << std::format(
            "requested addr: {:#x}, content_size: {:#x}\n", addr, section->content().size());
        
        auto range = contents | std::views::join | std::views::drop(start_offset) | std::views::take(content_size);
        auto range_test = contents | std::views::join | std::views::drop(start_offset);
        std::cout << "range_test size: " << std::ranges::distance(range_test)
                  << "\n";
        std::cout << std::format("start_offset: {:#x}, range size: {:#x}\n",
                                 start_offset, std::ranges::distance(range));
        
        auto vector = std::ranges::to<std::vector>(range);
        vector.resize(content_size);
        if (vector.size() != content_size) {
            std::fill(vector.begin() + vector.size(), vector.begin() + content_size, 0);
        }
        return vector;
    } else {
		throw std::runtime_error("Binary format not supported");
    }
    return {};
}

std::string BinaryView::viewHexChunk(size_t index) {
    auto addr = index * 0x10 + 0x1000;
    auto span = _binary->_lief_binary->get_content_from_virtual_address(addr, CHUNK_SIZE);
    std::vector<uint8_t> content = getSectionContentFromAddr(addr);
    return contentToHex(addr, content);
}
