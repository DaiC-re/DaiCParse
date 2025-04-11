#include "binary/binary.hpp"

#include <capstone/capstone.h>

#include <LIEF/ELF.hpp>
#include <LIEF/MachO.hpp>
#include <LIEF/PE.hpp>
#include <iostream>

Binary::Binary(const std::string path) {
    _lief_binary = LIEF::Parser::parse(path);
    if (_lief_binary == nullptr) {
        std::cerr << "Failed to parse the binary" << std::endl;
        exit(1);
    }
    for (auto& section : _lief_binary->sections()) {
        this->sections.push_back(BinSection(section.name(), section.content()));
    }
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, path);
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &_capstone_handle) != CS_ERR_OK)
        throw std::runtime_error("Failed to open handle with capstone");
}

Binary::Binary(std::istream& in) : _capstone_handle(0) {
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, in);
}

Binary::~Binary() {
    if (_capstone_handle != 0) cs_close(&_capstone_handle);
}
