#include "binary/binary.hpp"

#include <LIEF/PE.hpp>
#include <iostream>

static std::string contentToHex(const uintptr_t base_addr,
                                LIEF::span<const uint8_t> content) {
    std::stringstream hex_stream;

    for (int i = 0; i < content.size(); ++i) {
        if (i % 16 == 0) {
            hex_stream << std::hex << std::uppercase << std::setw(8)
                       << std::setfill('0') << base_addr + i << ": ";
        }
        hex_stream << std::hex << std::uppercase << std::setw(2)
                   << std::setfill('0') << static_cast<int>(content[i]) << " ";

        if ((i + 1) % 16 == 0) {
            hex_stream << "\n";
        }
    }
    return hex_stream.str();
}

Binary::Binary(const std::string path) {
    _lief_binary = LIEF::Parser::parse(path);
    if (_lief_binary == nullptr) {
        std::cerr << "Failed to parse the binary" << std::endl;
        exit(1);
    }
    for (auto& section : _lief_binary->sections()) {
        this->sections.push_back(Section{
            section.name(),
            contentToHex(section.virtual_address(), section.content())});
    }
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, path);
}

Binary::~Binary() {}
