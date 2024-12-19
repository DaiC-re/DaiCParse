#include "metadata/metadata.hpp"

#include <LIEF/PE.hpp>
#include <format>
#include <iostream>

#include "checksums/file_checksum.h"

BinaryMetadata::BinaryMetadata(const std::string& path) : _path(path) {
    _binary = LIEF::Parser::parse(path);
}

std::vector<BinaryMetadata::ExportedFn> BinaryMetadata::get_exports() {
    std::vector<ExportedFn> exported_functions = {};
    if (LIEF::PE::Binary::classof(_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary);
    }
    for (auto& exported_function : _binary->exported_functions()) {
        exported_functions.push_back(ExportedFn{
            std::format("0x{:x}", exported_function.address()),
            exported_function.name(),
        });
    }
    return exported_functions;
}

std::vector<BinaryMetadata::ImportedFn> BinaryMetadata::get_imports() {
    std::vector<ImportedFn> imported_functions = {};
    if (LIEF::PE::Binary::classof(_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary);
        for (auto& imported_file : pe.imports()) {
            for (auto& entry : imported_file.entries()) {
                imported_functions.push_back(
                    ImportedFn{0, imported_file.name(), entry.name()});
            }
        }
    }
    return imported_functions;
}

std::vector<std::pair<std::string, std::string>> BinaryMetadata::get_general() {
    std::vector<std::pair<std::string, std::string>> pairs;
    if (LIEF::PE::Binary::classof(_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary);
    }
    pairs.push_back(std::make_pair("Original size",
                                   std::to_string(_binary->original_size())));
    pairs.push_back(std::make_pair(
        "Image base", std::format("0x{:x}", _binary->imagebase())));
    std::string file_md5 = compute_md5_from_file(_path);
    pairs.push_back(std::make_pair("MD5", file_md5));
    return pairs;
}

static inline void add_dos_var(
    std::vector<std::pair<std::string, std::string>>& pairs, std::string name,
    int val) {
    pairs.push_back(std::make_pair(name, std::format("{:x}", val)));
}

std::vector<std::pair<std::string, std::string>> BinaryMetadata::get_dos() {
    std::vector<std::pair<std::string, std::string>> pairs;
    if (LIEF::PE::Binary::classof(_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary);
        auto& dos_header = pe.dos_header();
        add_dos_var(pairs, "Magic", dos_header.magic());
        add_dos_var(pairs, "Used Bytes in last page",
                    dos_header.used_bytes_in_last_page());
        add_dos_var(pairs, "Pages in file", dos_header.file_size_in_pages());
        add_dos_var(pairs, "Relocations", dos_header.numberof_relocation());
        add_dos_var(pairs, "Size of header in paragraphs",
                    dos_header.header_size_in_paragraphs());
        add_dos_var(pairs, "Minimum paragraphes needed",
                    dos_header.minimum_extra_paragraphs());
        add_dos_var(pairs, "Maximum paragraphes needed",
                    dos_header.maximum_extra_paragraphs());
        add_dos_var(pairs, "Initial (relative) SS value",
                    dos_header.initial_relative_ss());
        add_dos_var(pairs, "Initial SP value", dos_header.initial_sp());
        add_dos_var(pairs, "Checksum", dos_header.checksum());
        add_dos_var(pairs, "Initial IP value", dos_header.initial_ip());
        add_dos_var(pairs, "Initial (relative) CS value",
                    dos_header.initial_relative_cs());
        add_dos_var(pairs, "File address of relocation table",
                    dos_header.addressof_relocation_table());
        add_dos_var(pairs, "Overlay number",
                    dos_header.addressof_relocation_table());
        auto reserved = dos_header.reserved();
        pairs.push_back(
            std::make_pair("Reserved words [4]",
                           std::format("{} {} {} {}", reserved[0], reserved[1],
                                       reserved[2], reserved[3])));
        add_dos_var(pairs, "OEM identifier (for OEM information)",
                    dos_header.oem_id());
        add_dos_var(pairs, "OEM information", dos_header.oem_info());
        auto reserved2 = dos_header.reserved2();
        pairs.push_back(std::make_pair(
            "Reserved words [10]",
            std::format("{} {} {} {} {} {} {} {} {} {}", reserved2[0],
                        reserved2[1], reserved2[2], reserved2[3], reserved2[4],
                        reserved2[5], reserved2[6], reserved2[7], reserved2[8],
                        reserved2[9])));
        add_dos_var(pairs, "File address of new exe header",
                    dos_header.addressof_new_exeheader());
    }
    return pairs;
}