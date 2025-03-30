#include "binary/binary.hpp"

#include <LIEF/PE.hpp>
#include <iostream>
#include <lief/ELF.hpp>
#include <lief/MachO.hpp>

Binary::Binary(const std::string path) {
    _lief_binary = LIEF::Parser::parse(path);
    if (_lief_binary == nullptr) {
        std::cerr << "Failed to parse the binary" << std::endl;
        exit(1);
    }
    for (auto& section : _lief_binary->sections()) {
        this->sections.push_back(BinSection{section.name(), section.content()});
    }
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, path);
}

Binary::~Binary() {}
