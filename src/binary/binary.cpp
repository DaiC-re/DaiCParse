#include "binary/binary.hpp"

#include <capstone/capstone.h>

#include <LIEF/ELF.hpp>
#include <LIEF/MachO.hpp>
#include <LIEF/PE.hpp>
#include <iostream>
#include <optional>

Binary::Binary(const std::string path) {
    _lief_binary = LIEF::PE::Parser::parse(path);
    type = BinType::PE;
    if (_lief_binary == nullptr) {
        std::cerr << "Failed to parse the binary" << std::endl;
        exit(1);
    }

    if (LIEF::PE::Binary::classof(_lief_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_lief_binary);
        for (auto& section : pe.sections()) {
            this->sections.push_back(
                BinSection(section.name(), section.content(), section.padding(),
                           section.offset(), section.virtual_address(),
                           section.virtual_size()));
            std::cout
                << std::hex
                << std::format(
                       "Section: {}, size: {:x}, offset: {:x}, vaddr: {:x}\n",
                       section.name(), section.size(), section.offset(),
                       section.virtual_address());
        }
        for (auto& section : this->sections) {
            section.content = LIEF::span<const uint8_t>(section.content.data(),
                                                        section.content.size());
        }
    }
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, path);
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &_capstone_handle) != CS_ERR_OK)
        throw std::runtime_error("Failed to open handle with capstone");
    _text_section_relative_addr = getTextSection().virtual_addr;
    this->detectFunctions();
}

Binary::Binary(std::istream& in) : _capstone_handle(0) {
    metadata = std::make_unique<BinaryMetadata>(_lief_binary, in);
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &_capstone_handle) != CS_ERR_OK)
        throw std::runtime_error("Failed to open handle with capstone");
    //_text_section_relative_addr = getTextSection().virtual_addr;
}

Binary::~Binary() {
    if (_capstone_handle != 0) cs_close(&_capstone_handle);
}

inline void Binary::addCheckPoint(uintptr_t offset) {
    _disass_checkpoints.push_back(offset);
}

// Search for the closest checkpoint from the given address
// It returns the index (count of instruction) and real adress in the binary
std::pair<size_t, uintptr_t> Binary::closestCheckpointFromIndex(
    size_t instruction_ind) const {
    size_t index = instruction_ind / _instructions_per_checkpoint;
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

std::string Binary::getFunctionInstructions(uintptr_t start,
                                            uintptr_t end) const {
    auto view = std::views::join(sections);
    auto it = view.begin();
    std::advance(it, start - getTextSectionVirtualAddr());
    auto range =
        std::ranges::subrange(it, view.end()) | std::views::take(end - start);
    return this->contentToDisasm(start, range);
}

size_t Binary::instructionIndexFromAddr(uintptr_t addr) {
    const size_t addr_in_section = addr;
    auto checkpoint =
        std::lower_bound(_disass_checkpoints.begin(), _disass_checkpoints.end(),
                         addr_in_section);
    if (checkpoint != _disass_checkpoints.begin()) {
        --checkpoint;
    } else {
        throw std::runtime_error(
            "No checkpoint found before the given address");
    }
    auto current_addr = *checkpoint;
    std::cout << current_addr << " " << addr_in_section << "\n";
    for (auto& cp : _disass_checkpoints) {
        std::cout << cp << " ";
    }
    auto checkpoint_index =
        std::distance(_disass_checkpoints.begin(), checkpoint);

    const auto [next_checkpoint_index, next_checkpoint_addr] =
        nextCheckpointFromCheckpoint(checkpoint_index *
                                     _instructions_per_checkpoint);
    const auto selected_chunk_size = next_checkpoint_addr - current_addr;

    std::vector<uint8_t> bytes_vec =
        std::views::join(sections) |
        std::views::drop(current_addr - getTextSectionVirtualAddr()) |
        std::views::take(selected_chunk_size) |
        std::ranges::to<std::vector<uint8_t>>();

    cs_insn* insn = cs_malloc(_capstone_handle);
    size_t code_size = bytes_vec.size();
    const uint8_t* code_ptr = bytes_vec.data();
    auto current_index = checkpoint_index * _instructions_per_checkpoint;

    while (cs_disasm_iter(_capstone_handle, &code_ptr, &code_size,
                          &current_addr, insn)) {
        if (current_addr == addr_in_section) {
            uintptr_t target_address = insn->address;
            cs_free(insn, 1);
            return current_index;
        }
        std::cout << "Current address: " << std::hex << current_addr
                  << " Target address: " << std::hex << addr_in_section << "\n";
        ++current_index;
    }

    if (insn) {
        cs_free(insn, 1);
    }
    throw std::runtime_error(
        "Target instruction index not found in the given range.");
}

size_t Binary::getInstructionCount() const {
    if (_instruction_count == 0) {
        throw std::runtime_error("Instruction count was not set");
    }
    return _instruction_count;
}

uintptr_t Binary::getTextSectionVirtualAddr() const {
    return _text_section_relative_addr;
}

// uintptr_t Binary::getImageBase() const {
//     auto general = metadata->get_general();
//     auto finded = std::find_if(general.begin(), general.end(),
//                      [](auto& element) { return element.first == "Image
//                      base"; });
//     if (finded != general.end()) {
//         auto& val = *finded;
//         return std::stoi(val.second);
//     } else {
//         throw std::runtime_error(
//             "Couldn't find the image base in the metadatas");
//     }
// }

BinSection& Binary::getTextSection() {
    auto text_section_it =
        std::find_if(sections.begin(), sections.end(),
                     [](const BinSection& el) { return el.name == ".text"; });
    if (text_section_it == sections.end()) {
        throw std::runtime_error(
            "Couldn't find the .text section in the binary");
    }
    auto& text_section = *text_section_it;
    return text_section;
}

const BinSection& Binary::getTextSection() const {
    auto text_section_it =
        std::find_if(sections.begin(), sections.end(),
                     [](const BinSection& el) { return el.name == ".text"; });
    if (text_section_it == sections.end()) {
        throw std::runtime_error(
            "Couldn't find the .text section in the binary");
    }
    const auto& text_section = *text_section_it;
    return text_section;
}

void Binary::detectCalledFunctions(std::vector<uintptr_t>& called_functions,
                                   cs_insn* insn, size_t count) {
    size_t j;
    for (j = 0; j < count; j++) {
        auto& ins = insn[j];
        if (std::string_view(ins.mnemonic) == "call") {
            std::cout << "Found call instruction to: " << std::hex << ins.op_str
                      << "\n";
            // get ins.op_str in bytes

            try {
                called_functions.push_back(std::stoi(ins.op_str, nullptr, 16));
            } catch (const std::invalid_argument& e) {
            }

            // called_functions.push_back(std::hex(ins.op_str));
        }
    }
}

// Detect functions in the binary and also add checkpoints to load chunks of
// binary efficiently, will probably create an "analyzeBinary" function instead
void Binary::detectFunctions() {
    auto sections_range = std::ranges::join_view(sections);
    std::vector<uint8_t> bytes_vec =
        sections_range | std::ranges::to<std::vector<uint8_t>>();
    std::cout << "Bytes vector size: " << bytes_vec.size() << std::endl;
    cs_insn* insn;
    size_t count =
        cs_disasm(_capstone_handle, bytes_vec.data(), bytes_vec.size() - 1,
                  getTextSectionVirtualAddr(), 0, &insn);
    std::vector<uintptr_t> called_functions;
    if (count > 0) {
        detectCalledFunctions(called_functions, insn, count);
        size_t j;
        uintptr_t current_function_start = 0;
        uintptr_t ret_instructions = 0;
        for (j = 0; j < count; j++) {
            auto& ins = insn[j];

            if (j % _instructions_per_checkpoint == 0) {
                std::cout << "Added breakpoint <3\n";
                addCheckPoint(ins.address);
            }
            // Detect function prologue for x86_64: push rbp; mov rbp, rsp
            // if (ins.bytes[0] == 0x55 && std::string_view(ins.op_str) ==
            // "rbp") { if (current_function_start != 0 && ret_instructions !=
            // 0) { add_function(current_function_start, ret_instructions);
            // ret_instructions = 0;
            // }
            // std::cout
            // << std::hex << ins.address
            // << " Found function prologue (push rbp; mov rbp, rsp)\n";
            // current_function_start = ins.address;
            // }

            // Detect function prologue for x86: push ebp; mov ebp, esp
            // if (ins.bytes[0] == 0x55 && std::string_view(ins.op_str) ==
            // "ebp") { if (current_function_start != 0 && ret_instructions !=
            // 0) { add_function(current_function_start, ret_instructions);
            // ret_instructions = 0;
            // }
            // for (auto byte : ins.bytes) {
            // std::cout << std::hex << static_cast<int>(byte) << " ";
            // }
            // std::cout << ins.mnemonic << " size: " << ins.op_str << "\n";
            // std::cout
            // << "Found x86 function prologue (push ebp; mov ebp, esp)\n";
            // current_function_start = ins.address;
            // }
            // Store the last ret instruction until the next function start and
            // return the last ret instruction to get the function end

            // Function qui chercherait � d�tecter tout les calls et qui
            // sauvegarde l'adresse de destination dans un vecteur, une fois
            // qu'on a ce vecteur on peut commencer detectFunctions classique,
            // si on est � une adresse qui est dans le vecteur, on met
            // current_function_start � cette adresse
            if (std::find(called_functions.begin(), called_functions.end(),
                          ins.address) != called_functions.end()) {
                if (current_function_start != 0 && ret_instructions != 0) {
                    add_function(current_function_start, ret_instructions, j);
                    ret_instructions = 0;
                }
                current_function_start = ins.address;
            }
            if (std::string_view(ins.mnemonic) == "ret") {
                std::cout << "Found ret\n";
                ret_instructions = ins.address + ins.size;
            }
        }
        for (auto& fn : _functions) {
            std::cout << fn.getStart() << " " << fn.getEnd() << " "
                      << fn.getName() << std::endl;
        }
        addCheckPoint(insn[count - 1].address);
        _instruction_count = count;
        std::cout << "instruction count: " << std::dec << _instruction_count
                  << std::endl;
        cs_free(insn, count);
        _instruction_count = count;
    }
}

std::optional<Binary::Function> Binary::get_function(std::string& name) {
    for (auto& fn : _functions) {
        if (fn.getName() == name) {
            return std::optional<Binary::Function>(fn);
        }
    }
}

void Binary::add_function(uintptr_t start, uintptr_t end, int size) {
    auto function_name = std::string("function_") + std::format("{:x}", start);
    _functions.push_back(Function(function_name, start, end, size));
}

void Binary::Function::serialize(std::ostream& out) const {
    uint32_t nameSize = _name.size();
    out.write(reinterpret_cast<const char*>(&nameSize), sizeof(nameSize));
    out.write(_name.data(), nameSize);

    out.write(reinterpret_cast<const char*>(&_start), sizeof(uintptr_t));
    out.write(reinterpret_cast<const char*>(&_end), sizeof(uintptr_t));
    out.write(reinterpret_cast<const char*>(&_id), sizeof(uint64_t));
}

void Binary::Function::deserialize(std::istream& in) {
    uint32_t nameSize = 0;
    in.read(reinterpret_cast<char*>(&nameSize), sizeof(nameSize));
    _name.resize(nameSize);
    in.read(_name.data(), nameSize);

    in.read(reinterpret_cast<char*>(&_start), sizeof(uintptr_t));
    in.read(reinterpret_cast<char*>(&_end), sizeof(uintptr_t));
    in.read(reinterpret_cast<char*>(&_id), sizeof(uint64_t));
}

Binary::Function* Binary::getFunctionAtAdress(uintptr_t addr) {
    for (auto& func : _functions) {
        if (addr == func.getStart()) {
            return &func;
        }
    }
    return nullptr;
}

const Binary::Function* Binary::getFunctionAtAdress(uintptr_t addr) const {
    for (auto& func : _functions) {
        if (addr == func.getStart()) {
            return &func;
        }
    }
    return nullptr;
}

BinSection* Binary::section_from_rva(uint64_t virtual_address) {
    const auto it_section = std::find_if(
        std::begin(sections), std::end(sections),
        [virtual_address](const BinSection& section) {
            return section.virtual_addr <= virtual_address &&
                   virtual_address <
                       (section.virtual_addr + section.virtual_size);
        });

    if (it_section == std::end(sections)) {
        return nullptr;
    }

    return &(*it_section);
}
