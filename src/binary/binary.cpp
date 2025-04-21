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
        this->sections.push_back(
            BinSection(section.name(), section.content(), section.offset()));
    }
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, path);
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &_capstone_handle) != CS_ERR_OK)
        throw std::runtime_error("Failed to open handle with capstone");
    this->detectFunctions();
}

Binary::Binary(std::istream& in) : _capstone_handle(0) {
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, in);
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &_capstone_handle) != CS_ERR_OK)
        throw std::runtime_error("Failed to open handle with capstone");
}

Binary::~Binary() {
    if (_capstone_handle != 0) cs_close(&_capstone_handle);
}

void Binary::detectFunctions() {
    auto text_section_it =
        std::find_if(sections.begin(), sections.end(),
                     [](const BinSection& el) { return el.name == ".text"; });
    if (text_section_it == sections.end()) {
        throw std::runtime_error(
            "Couldn't find the .text section in the binary");
    }
    auto text_section = *text_section_it;

    std::vector<uint8_t> bytes_vec =
        text_section | std::ranges::to<std::vector<uint8_t>>();
    cs_insn* insn;
    size_t count = cs_disasm(_capstone_handle, bytes_vec.data(),
                             bytes_vec.size() - 1, 0x401000, 0, &insn);
    // std::cout << "counnnnt: " << bytes_vec.size() << " "
    //           << " " << count << std::endl;
    if (count > 0) {
        size_t j;
        uintptr_t current_function_start = 0;
        for (j = 0; j < count; j++) {
            auto& ins = insn[j];
            // std::cout << std::hex << "addr " << ins.address << " byte "
            //           << static_cast<int>(ins.bytes[0]) << "\"" <<
            //           ins.mnemonic
            //           << "\"" << std::endl;
            // Detect function prologue for x86_64: push rbp; mov rbp, rsp
            if (ins.bytes[0] == 0x55 && std::string_view(ins.op_str) == "rbp") {
                std::cout
                    << std::hex << ins.address
                    << " Found function prologue (push rbp; mov rbp, rsp)\n";
                current_function_start = ins.address;
            }

            // Detect function prologue for x86: push ebp; mov ebp, esp
            if (ins.bytes[0] == 0x55 && std::string_view(ins.op_str) == "ebp") {
                for (auto byte : ins.bytes) {
                    std::cout << std::hex << static_cast<int>(byte) << " ";
                }
                std::cout << ins.mnemonic << " size: " << ins.op_str << "\n";
                std::cout
                    << "Found x86 function prologue (push ebp; mov ebp, esp)\n";
                current_function_start = ins.address;
            }

            if (std::string_view(ins.mnemonic) == "call") {
                std::cout << "Found call instruction to: " << std::hex
                          << ins.op_str << "\n";
            }

            if (std::string_view(ins.mnemonic) == "ret") {
                std::cout << "Found ret\n";
                auto function_end = ins.address + ins.size;
                auto function_name =
                    std::string("function_") +
                    std::format("{:x}", current_function_start);
                _functions.push_back(Function(
                    function_name, current_function_start, function_end));
                current_function_start = 0;
            }
        }
        for (auto& fn : _functions) {
            std::cout << fn.getStart() << " " << fn.getEnd() << " "
                      << fn.getName() << std::endl;
        }
        cs_free(insn, count);
    }
}

void Binary::Function::serialize(std::ostream& out) const {
    uint32_t nameSize = _name.size();
    out.write(reinterpret_cast<const char*>(&nameSize), sizeof(nameSize));
    out.write(_name.data(), nameSize);

    out.write(reinterpret_cast<const char*>(&_start), sizeof(uintptr_t));
    out.write(reinterpret_cast<const char*>(&_end), sizeof(uintptr_t));
}

void Binary::Function::deserialize(std::istream& in) {
    uint32_t nameSize = 0;
    in.read(reinterpret_cast<char*>(&nameSize), sizeof(nameSize));
    _name.resize(nameSize);
    in.read(_name.data(), nameSize);

    in.read(reinterpret_cast<char*>(&_start), sizeof(uintptr_t));
    in.read(reinterpret_cast<char*>(&_end), sizeof(uintptr_t));
}
