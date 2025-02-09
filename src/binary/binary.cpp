#include "binary/binary.hpp"

#include <LIEF/PE.hpp>
#include <iostream>

Binary::Binary(const std::string path) {
    _lief_binary = LIEF::Parser::parse(path);
    _metadata = std::make_unique<BinaryMetadata>(_lief_binary, path);
}

Binary::~Binary() {}
