#pragma once
#include <capstone/capstone.h>

#include <LIEF/ELF/Binary.hpp>
#include <format>
#include <iostream>
#include <optional>
#include <ranges>
#include <sstream>
#include <string>

#include "bin_section.hpp"
#include "metadata/metadata.hpp"

enum class BinType { ELF, PE, MACHO, UNKNOWN };

class Binary {
   public:
    Binary() : _capstone_handle(0) {};
    Binary(std::istream& in);
    Binary(const std::string path);
    ~Binary();

    size_t getInstructionCount() const;
    uintptr_t getTextSectionVirtualAddr() const;
    // uintptr_t getImageBase() const;
    BinSection& getTextSection();
    const BinSection& getTextSection() const;
    std::pair<size_t, uintptr_t> closestCheckpointFromIndex(
        size_t instruction_ind) const;
    std::pair<size_t, uintptr_t> nextCheckpointFromCheckpoint(
        size_t instruction_ind) const;
    std::string getFunctionInstructions(uintptr_t start, uintptr_t end) const;

    void setInstructionCount(size_t count) { _instruction_count = count; }

    BinSection* section_from_rva(uint64_t virtual_address);

    class Function {
       public:
        Function() {};
        Function(std::string name, uintptr_t start, uintptr_t end, size_t id)
            : _name(name), _start(start), _end(end), _id(id) {}

        const std::string getName() const { return _name; }
        uintptr_t getStart() const { return _start; }
        uintptr_t getEnd() const { return _end; }
        uintptr_t getSize() const { return _end - _start; }
        void serialize(std::ostream& out) const;
        void deserialize(std::istream& in);
        uint64_t getId() const { return _id; }
        void setName(const std::string& name) { _name = name; }
        bool operator==(const Function& other) const {
            return _name == other._name && _start == other._start &&
                   _end == other._end;
        };

       private:
        std::string _name;
        uintptr_t _start;
        uintptr_t _end;
        uint64_t _id;
    };

    template <typename Range>
    requires std::ranges::range<Range> std::string contentToDisasm(
        const uintptr_t base_addr, const Range& view) const {
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

    template <typename Range>
    requires std::ranges::range<Range> uintptr_t getTargetFromCheckpoint(
        std::pair<size_t, uintptr_t> checkpoint, size_t target_index,
        const Range& view_from_checkpoint) {
        size_t current_index = checkpoint.first;
        uintptr_t current_address = checkpoint.second;
        auto [next_checkpoint_index, next_checkpoint_addr] =
            nextCheckpointFromCheckpoint(current_index);
        auto selected_chunk_size = next_checkpoint_addr - current_address;

        std::vector<uint8_t> bytes_vec =
            view_from_checkpoint | std::views::take(selected_chunk_size) |
            std::ranges::to<std::vector<uint8_t>>();

        cs_insn* insn = cs_malloc(_capstone_handle);
        size_t code_size = bytes_vec.size();
        const uint8_t* code_ptr = bytes_vec.data();

        while (cs_disasm_iter(_capstone_handle, &code_ptr, &code_size,
                              &current_address, insn)) {
            if (current_index == target_index) {
                uintptr_t target_address = insn->address;
                cs_free(insn, 1);
                return target_address;
            }
            ++current_index;
        }

        if (insn) {
            cs_free(insn, 1);
        }
        throw std::runtime_error(
            "Target instruction index not found in the given range.");
    }
    size_t instructionIndexFromAddr(uintptr_t addr);

   private:
    void detectFunctions();
    inline void addCheckPoint(uintptr_t offset);
    void add_function(uintptr_t start, uintptr_t end, int size);
    void detectCalledFunctions(std::vector<uintptr_t>& called_functions,
                               cs_insn* insn, size_t count);

   public:
    std::optional<Function> get_function(std::string&);
    std::unique_ptr<BinaryMetadata> metadata;
    std::vector<BinSection> sections;
    std::vector<Function> _functions;
    std::vector<uintptr_t> _disass_checkpoints;
    std::unique_ptr<LIEF::Binary> _lief_binary;
    BinType type = BinType::UNKNOWN;
    const size_t _instructions_per_checkpoint = 100;
    uintptr_t _text_section_relative_addr = 0;
    Function* getFunctionAtAdress(uintptr_t addr);
    const Function* getFunctionAtAdress(uintptr_t addr) const;

   private:
    csh _capstone_handle;
    size_t _instruction_count = 0;
};
