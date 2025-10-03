#pragma once

#include <sstream>
#include <format>

template <typename Range>
requires std::ranges::range<Range> std::string contentToHex(
    const uintptr_t base_addr, const Range& view) {
    std::stringstream hex_stream;

    size_t i = 0;
    for (const auto& byte : view) {
        if (i % 16 == 0) {
            hex_stream << std::format("{:08X}: ", base_addr + i);
        }

        hex_stream << std::format("{:02X} ", static_cast<int>(byte));

        if ((i + 1) % 16 == 0) {
            hex_stream << "\n";
        }
        ++i;
    }

    return hex_stream.str();
}
