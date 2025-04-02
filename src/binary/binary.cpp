#include "binary/binary.hpp"

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
        this->sections.push_back(BinSection{section.name(), section.content()});
    }
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, path);
}

Binary::Binary(std::istream &in)
{
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, in);
}

Binary::~Binary() {}

void Binary::Section::serialize(std::ostream &out) const {
    uint32_t nameSize = name.size();
    out.write(reinterpret_cast<const char*>(&nameSize), sizeof(nameSize));
    out.write(name.data(), nameSize);

    uint32_t contentSize = content.size();
    out.write(reinterpret_cast<const char*>(&contentSize), sizeof(contentSize));
    out.write(content.data(), contentSize);
}

void Binary::Section::deserialize(std::istream &in) {
    uint32_t nameSize;
    in.read(reinterpret_cast<char*>(&nameSize), sizeof(nameSize));
    name.resize(nameSize);
    in.read(name.data(), nameSize);

    uint32_t contentSize;
    in.read(reinterpret_cast<char*>(&contentSize), sizeof(contentSize));
    content.resize(contentSize);
    in.read(content.data(), contentSize);
}
