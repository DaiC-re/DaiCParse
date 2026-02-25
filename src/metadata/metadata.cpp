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

BinaryMetadata::BinaryMetadata(const std::unique_ptr<LIEF::Binary>& binary,
                               std::istream& in)
    : _binary(binary) {
    deserialize(in);
}

void BinaryMetadata::serialize(std::ostream& out) const {
    uint32_t pathSize = _path.size();
    out.write(reinterpret_cast<const char*>(&pathSize), sizeof(pathSize));
    out.write(_path.data(), pathSize);

    serializePairs(this->general_infos, out);
    serializePairs(this->file_headers, out);
    serializePairs(this->dos_headers, out);
    this->serializeExported(exported_functions, out);
    this->serializeImported(imported_functions, out);
}

void BinaryMetadata::deserialize(std::istream& in) {
    uint32_t pathSize;
    in.read(reinterpret_cast<char*>(&pathSize), sizeof(pathSize));
    _path.resize(pathSize);
    in.read(_path.data(), pathSize);

    deserializePairs(this->general_infos, in);
    deserializePairs(this->file_headers, in);
    deserializePairs(this->dos_headers, in);
    this->deserializeExported(exported_functions, in);
    this->deserializeImported(imported_functions, in);
}

void BinaryMetadata::serializePairs(
    std::vector<std::pair<std::string, std::string>> metadata_vector,
    std::ostream& out) const {
    uint32_t numPairs = metadata_vector.size();
    out.write(reinterpret_cast<const char*>(&numPairs), sizeof(numPairs));

    for (const auto& pair : metadata_vector) {
        uint32_t firstStringSize = pair.first.size();
        out.write(reinterpret_cast<const char*>(&firstStringSize),
                  sizeof(firstStringSize));
        out.write(pair.first.data(), firstStringSize);

        uint32_t secondStringSize = pair.second.size();
        out.write(reinterpret_cast<const char*>(&secondStringSize),
                  sizeof(secondStringSize));
        out.write(pair.second.data(), secondStringSize);
    }
}

void BinaryMetadata::deserializePairs(
    std::vector<std::pair<std::string, std::string>>& metadata_vector,
    std::istream& in) {
    try {
        uint32_t numPairs;
        in.read(reinterpret_cast<char*>(&numPairs), sizeof(numPairs));

        metadata_vector.resize(numPairs);
        for (auto& pair : metadata_vector) {
            uint32_t firstStringSize;
            in.read(reinterpret_cast<char*>(&firstStringSize),
                    sizeof(firstStringSize));
            pair.first.resize(firstStringSize);
            in.read(pair.first.data(), firstStringSize);

            uint32_t secondStringSize;
            in.read(reinterpret_cast<char*>(&secondStringSize),
                    sizeof(secondStringSize));
            pair.second.resize(secondStringSize);
            in.read(pair.second.data(), secondStringSize);
        }
    } catch (std::bad_alloc& ba) {
    }
}

void BinaryMetadata::serializeExported(std::vector<ExportedFn> exported,
                                       std::ostream& out) const {
    uint32_t numFn = exported.size();
    out.write(reinterpret_cast<const char*>(&numFn), sizeof(numFn));

    for (const auto& fn : exported) {
        uint32_t addressSize = fn.address.size();
        out.write(reinterpret_cast<const char*>(&addressSize),
                  sizeof(addressSize));
        out.write(fn.address.data(), addressSize);
        uint32_t nameSize = fn.fonction_name.size();
        out.write(reinterpret_cast<const char*>(&nameSize), sizeof(nameSize));
        out.write(fn.fonction_name.data(), nameSize);
    }
}

void BinaryMetadata::deserializeExported(std::vector<ExportedFn>& exported,
                                         std::istream& in) {
    try {
        uint32_t numFn;
        in.read(reinterpret_cast<char*>(&numFn), sizeof(numFn));

        exported.resize(numFn);
        for (auto& fn : exported) {
            uint32_t addressSize;
            in.read(reinterpret_cast<char*>(&addressSize), sizeof(addressSize));
            fn.address.resize(addressSize);
            in.read(fn.address.data(), addressSize);

            uint32_t nameSize;
            in.read(reinterpret_cast<char*>(&nameSize), sizeof(nameSize));
            fn.fonction_name.resize(nameSize);
            in.read(fn.fonction_name.data(), nameSize);
        }
    } catch (std::bad_alloc& ba) {
    }
}

void BinaryMetadata::serializeImported(std::vector<ImportedFn> imported,
                                       std::ostream& out) const {
    uint32_t numFn = imported.size();
    out.write(reinterpret_cast<const char*>(&numFn), sizeof(numFn));

    for (const auto& fn : imported) {
        out.write(reinterpret_cast<const char*>(&fn.offset), sizeof(fn.offset));
        uint32_t filenameSize = fn.file_name.size();
        out.write(reinterpret_cast<const char*>(&filenameSize),
                  sizeof(filenameSize));
        out.write(fn.file_name.data(), filenameSize);
        uint32_t nameSize = fn.fonction_name.size();
        out.write(reinterpret_cast<const char*>(&nameSize), sizeof(nameSize));
        out.write(fn.fonction_name.data(), nameSize);
    }
}

void BinaryMetadata::deserializeImported(std::vector<ImportedFn>& imported,
                                         std::istream& in) {
    try {
        uint32_t numFn;
        in.read(reinterpret_cast<char*>(&numFn), sizeof(numFn));

        imported.resize(numFn);
        for (auto& fn : imported) {
            in.read(reinterpret_cast<char*>(&fn.offset), sizeof(fn.offset));
            uint32_t filenameSize;
            in.read(reinterpret_cast<char*>(&filenameSize),
                    sizeof(filenameSize));
            fn.file_name.resize(filenameSize);
            in.read(fn.file_name.data(), filenameSize);

            uint32_t nameSize;
            in.read(reinterpret_cast<char*>(&nameSize), sizeof(nameSize));
            fn.fonction_name.resize(nameSize);
            in.read(fn.fonction_name.data(), nameSize);
        }
    } catch (std::bad_alloc& ba) {
    }
}
