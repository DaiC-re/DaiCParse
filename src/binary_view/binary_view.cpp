#include "binary_view/binary_view.hpp"
#include "hex_utils/hex_utils.hpp"
#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/Section.hpp>

constexpr size_t CHUNK_SIZE = 0x1000;

BinaryView::BinaryView(const std::unique_ptr<Binary> &binary)
    : _binary(binary) {}

LIEF::Section* BinaryView::getSectionAtAddr(uintptr_t virtual_addr) {
    const auto &sections = _binary->_lief_binary->sections();

    std::cout << std::format("Looking for section at addr: {:#x}\n",
                             virtual_addr);

    LIEF::Section *closest = nullptr;
    uintptr_t closest_addr = 0;

    for (auto &section : sections) {
        auto sec_addr = section.virtual_address();
        if (sec_addr <= virtual_addr) {
            if (!closest || sec_addr > closest_addr) {
                closest = &section;
                closest_addr = sec_addr;
            }
        }
    }
    return closest;
}

LIEF::Section *BinaryView::getNextSection(LIEF::Section *section) {
    auto sections = _binary->_lief_binary->sections();

    auto section_it = std::find_if(sections.begin(), sections.end(),
                                   [section](auto &sec) { return &sec == section; });
    ++section_it;

    if (section_it == sections.end()) {
        return nullptr;
    }
    return &(*section_it);
}

std::vector<uint8_t> BinaryView::getSectionContentFromAddr(size_t addr, size_t content_size = CHUNK_SIZE) {
    if (LIEF::PE::Binary::classof(_binary->_lief_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary->_lief_binary);

        LIEF::PE::Section *section = pe.section_from_rva(addr);
        std::cout << std::format(
            "addr: {:#x}, section: {}\n", addr,
            section != nullptr ? section->name() : "nullptr");
        if (section == nullptr) {
            std::cerr << "No section found at this address, dev error\n";
            section = static_cast<LIEF::PE::Section *>(getSectionAtAddr(addr));
        }
        std::array<LIEF::span<const uint8_t>, 2> contents = {
            section->content(), section->padding()};
        auto start_offset = addr - section->virtual_address();
        std::cout << std::format(
            "addr: {:#x}, section addr: {:#x}, start_offset: {:#x}\n",
                                 addr, section->virtual_address(), start_offset);
        auto i = 0;
        auto range = contents | std::views::join | std::views::drop(start_offset) | std::views::take(content_size);
        std::vector<uint8_t> vector = std::ranges::to<std::vector>(range);
        vector.resize(content_size);
        if (vector.size() != content_size) {
            auto next_section = getNextSection(section);
            if (addr + content_size >= next_section->virtual_address()) {
                auto second_vector =
                    getSectionContentFromAddr(next_section->virtual_address(),
                                              content_size - vector.size());
                vector.insert(vector.end(), second_vector.begin(), second_vector.end());
            }
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
