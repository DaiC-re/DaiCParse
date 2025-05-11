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
        this->sections.push_back(BinSection(section.name(), section.content(),
                                            section.offset(),
                                            section.virtual_address()));
    }
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, path);
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &_capstone_handle) != CS_ERR_OK)
        throw std::runtime_error("Failed to open handle with capstone");
    this->detectFunctions();
}

Binary::Binary(std::istream& in) : _capstone_handle(0) {
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, in);
}

Binary::~Binary() {
    if (_capstone_handle != 0) cs_close(&_capstone_handle);
}

inline void Binary::addCheckPoint(uintptr_t offset) {
    _disass_checkpoints.push_back(offset);
}

// Search for the closest checkpoint from the given address
// It returns the index (count of instruction) and real adress in the binary
std::pair<size_t, uintptr_t> Binary::closestCheckpointFromAddr(
    size_t instruction_ind) const {
    int index = instruction_ind / _instructions_per_checkpoint;
    auto closest_addr = _disass_checkpoints[index];
    return {index * _instructions_per_checkpoint, closest_addr};
}

std::pair<size_t, uintptr_t> Binary::nextCheckpointFromCheckpoint(
    size_t checkpoint_ins_index) const {
    auto checkpoint_index = checkpoint_ins_index / _instructions_per_checkpoint;
    auto next_checkpoint_addr = _disass_checkpoints[checkpoint_index + 1];
    return {checkpoint_ins_index + _instructions_per_checkpoint,
            next_checkpoint_addr};
}

size_t Binary::getInstructionCount() const {
    if (_instruction_count == 0) {
        throw std::runtime_error("Instruction count was not set");
    }
    return _instruction_count;
}

uintptr_t Binary::getTextSectionOffset() const { return _text_section_offset; }

// Detect functions in the binary and also add checkpoints to load chunks of
// binary efficiently, will probably create an "analyzeBinary" function instead
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
    size_t count =
        cs_disasm(_capstone_handle, bytes_vec.data(), bytes_vec.size() - 1,
                  text_section.offset, 0, &insn);
    _text_section_offset = text_section.offset;
    if (count > 0) {
        size_t j;
        uintptr_t current_function_start = 0;
        for (j = 0; j < count; j++) {
            auto& ins = insn[j];

            if (j % _instructions_per_checkpoint == 0) {
                std::cout << "Added breakpoint <3\n";
                addCheckPoint(ins.address - text_section.offset);
            }
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
        _instruction_count = count;
    }
}
