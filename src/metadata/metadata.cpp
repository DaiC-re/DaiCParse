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