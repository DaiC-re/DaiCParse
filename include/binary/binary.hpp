#pragma once
#include <capstone/capstone.h>

#include <LIEF/ELF/Binary.hpp>
#include <format>
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
    Binary() : _capstone_handle(0){};
    Binary(std::istream& in);
    Binary(const std::string path);
    ~Binary();

    class Function {
       public:
        Function() {};
        Function(std::string name, uintptr_t start, uintptr_t end)
            : _name(name), _start(start), _end(end) {}

        std::string getName() const { return _name; }
        uintptr_t getStart() const { return _start; }
        uintptr_t getEnd() const { return _end; }

        void serialize(std::ostream &out) const;
        void deserialize(std::istream &in);
       private:
        std::string _name;
        uintptr_t _start;
        uintptr_t _end;
    };

    template <typename Range>
    requires std::ranges::range<Range> std::string contentToDisasm(
        const uintptr_t base_addr, const Range& view) {
        std::stringstream disasm_stream;
        std::vector<uint8_t> bytes_vec =
            view | std::ranges::to<std::vector<uint8_t>>();

        cs_insn* insn;
        size_t count = cs_disasm(_capstone_handle, bytes_vec.data(),
                                 bytes_vec.size() - 1, base_addr, 0, &insn);
        if (count > 0) {
            size_t j;
            for (j = 0; j < count; j++) {
                disasm_stream
                    << std::format("0x{:016X}:\t{}\t\t{}\n", insn[j].address,
                                   insn[j].mnemonic, insn[j].op_str);
            }

            cs_free(insn, count);
        } else
            printf("ERROR: Failed to disassemble given code!\n");
        return disasm_stream.str();
    }

   private:
    void detectFunctions();
    void add_function(uintptr_t start, uintptr_t end);
    void detectCalledFunctions(std::vector<uintptr_t> &called_functions, cs_insn *insn, size_t count);
   public:
    std::unique_ptr<BinaryMetadata> metadata;
    std::vector<BinSection> sections;
    std::vector<Function> _functions;

   private:
    std::unique_ptr<LIEF::Binary> _lief_binary;
    csh _capstone_handle;
};

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
