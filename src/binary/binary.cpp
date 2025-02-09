#include "binary/binary.hpp"

#include <LIEF/PE.hpp>
#include <iostream>

Binary::Binary(const std::string path) {
    _lief_binary = LIEF::Parser::parse(path);
    if (_lief_binary == nullptr) {
        std::cerr << "Failed to parse the binary" << std::endl;
        exit(1);
    }
    _metadata = std::make_unique<BinaryMetadata>(_lief_binary, path);
}

Binary::~Binary() {}
