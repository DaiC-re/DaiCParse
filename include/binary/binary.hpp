#pragma once
#include <LIEF/ELF/Binary.hpp>
#include <iomanip>
#include <iostream>
#include <ranges>
#include <span>
#include <sstream>
#include <string>

#include "hex_iterator.hpp"
#include "metadata/metadata.hpp"

class Binary {
   public:
    Binary(const std::string path);
    ~Binary();
    void get_bytes();

   public:
    std::unique_ptr<BinaryMetadata> metadata;
    std::vector<BinSection> sections;

   private:
    std::unique_ptr<LIEF::Binary> _lief_binary;
};

template <typename Range>
requires std::ranges::range<Range> std::string contentToHex(
    const uintptr_t base_addr, const Range& view) {
    std::stringstream hex_stream;

    size_t i = 0;
    for (const auto& byte : view) {
        if (i % 16 == 0) {
            hex_stream << std::hex << std::uppercase << std::setw(8)
                       << std::setfill('0') << base_addr + i << ": ";
        }

        hex_stream << std::hex << std::uppercase << std::setw(2)
                   << std::setfill('0') << static_cast<int>(byte) << " ";

        if ((i + 1) % 16 == 0) {
            hex_stream << "\n";
        }
        ++i;
    }

    return hex_stream.str();
}