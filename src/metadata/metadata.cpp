#include "metadata/metadata.hpp"

#include <LIEF/PE.hpp>
#include <format>
#include <iostream>

#include "checksums/file_checksum.h"

BinaryMetadata::BinaryMetadata(const std::unique_ptr<LIEF::Binary>& binary,
                               const std::string& path)
    : _binary(binary), _path(path) {
    this->parse_dos();
    this->parse_exports();
    this->parse_general();
    this->parse_header();
    this->parse_imports();
}

void BinaryMetadata::parse_exports() {
    if (LIEF::PE::Binary::classof(_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary);
    }
    for (auto& exported_function : _binary->exported_functions()) {
        exported_functions.push_back(ExportedFn{
            std::format("0x{:X}", exported_function.address()),
            exported_function.name(),
        });
    }
}

void BinaryMetadata::parse_imports() {
    if (LIEF::PE::Binary::classof(_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary);
        for (auto& imported_file : pe.imports()) {
            for (auto& entry : imported_file.entries()) {
                imported_functions.push_back(
                    ImportedFn{0, imported_file.name(), entry.name()});
            }
        }
    }
}

void BinaryMetadata::parse_general() {
    if (LIEF::PE::Binary::classof(_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary);
    }
    general_infos.push_back(std::make_pair(
        "Original size", std::to_string(_binary->original_size())));
    general_infos.push_back(std::make_pair(
        "Image base", std::format("0x{:X}", _binary->imagebase())));
    std::string file_md5 = compute_md5_from_file(_path);
    general_infos.push_back(std::make_pair("MD5", file_md5));
}

void BinaryMetadata::parse_header() {
    if (LIEF::PE::Binary::classof(_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary);
        auto header = pe.header();
        file_headers.push_back(
            std::make_pair("Machine", LIEF::PE::to_string(header.machine())));
        file_headers.push_back(std::make_pair(
            "Sections count", std::to_string(header.numberof_sections())));
        file_headers.push_back(std::make_pair(
            "Time Date Stamp", std::to_string(header.time_date_stamp())));
        file_headers.push_back(
            std::make_pair("Ptr to Symbol table",
                           std::to_string(header.pointerto_symbol_table())));
        file_headers.push_back(std::make_pair(
            "Number of symbols", std::to_string(header.numberof_symbols())));
        file_headers.push_back(
            std::make_pair("Size of optional header",
                           std::to_string(header.sizeof_optional_header())));
        file_headers.push_back(
            std::make_pair("Characteristics raw value",
                           std::format("{:X}", header.characteristics())));
    }
}

static inline void add_dos_var(
    std::vector<std::pair<std::string, std::string>>& pairs, std::string name,
    int val) {
    pairs.push_back(std::make_pair(name, std::format("{:X}", val)));
}

void BinaryMetadata::parse_dos() {
    if (LIEF::PE::Binary::classof(_binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*_binary);
        auto& dos_header = pe.dos_header();
        add_dos_var(dos_headers, "Magic", dos_header.magic());
        add_dos_var(dos_headers, "Used Bytes in last page",
                    dos_header.used_bytes_in_last_page());
        add_dos_var(dos_headers, "Pages in file",
                    dos_header.file_size_in_pages());
        add_dos_var(dos_headers, "Relocations",
                    dos_header.numberof_relocation());
        add_dos_var(dos_headers, "Size of header in paragraphs",
                    dos_header.header_size_in_paragraphs());
        add_dos_var(dos_headers, "Minimum paragraphes needed",
                    dos_header.minimum_extra_paragraphs());
        add_dos_var(dos_headers, "Maximum paragraphes needed",
                    dos_header.maximum_extra_paragraphs());
        add_dos_var(dos_headers, "Initial (relative) SS value",
                    dos_header.initial_relative_ss());
        add_dos_var(dos_headers, "Initial SP value", dos_header.initial_sp());
        add_dos_var(dos_headers, "Checksum", dos_header.checksum());
        add_dos_var(dos_headers, "Initial IP value", dos_header.initial_ip());
        add_dos_var(dos_headers, "Initial (relative) CS value",
                    dos_header.initial_relative_cs());
        add_dos_var(dos_headers, "File address of relocation table",
                    dos_header.addressof_relocation_table());
        add_dos_var(dos_headers, "Overlay number",
                    dos_header.addressof_relocation_table());
        auto reserved = dos_header.reserved();
        dos_headers.push_back(
            std::make_pair("Reserved words [4]",
                           std::format("{} {} {} {}", reserved[0], reserved[1],
                                       reserved[2], reserved[3])));
        add_dos_var(dos_headers, "OEM identifier (for OEM information)",
                    dos_header.oem_id());
        add_dos_var(dos_headers, "OEM information", dos_header.oem_info());
        auto reserved2 = dos_header.reserved2();
        dos_headers.push_back(std::make_pair(
            "Reserved words [10]",
            std::format("{} {} {} {} {} {} {} {} {} {}", reserved2[0],
                        reserved2[1], reserved2[2], reserved2[3], reserved2[4],
                        reserved2[5], reserved2[6], reserved2[7], reserved2[8],
                        reserved2[9])));
        add_dos_var(dos_headers, "File address of new exe header",
                    dos_header.addressof_new_exeheader());
    }
}