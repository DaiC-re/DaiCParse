#include "metadata/metadata.hpp"

#include <LIEF/PE.hpp>
#include <iostream>

BinaryMetadata::BinaryMetadata(std::unique_ptr<LIEF::Binary>& binary)
    : _binary(binary) {
    if (LIEF::PE::Binary::classof(binary.get())) {
        auto& pe = static_cast<LIEF::PE::Binary&>(*binary);
        std::cout << "== Dos Header ==" << '\n';
        std::cout << pe.dos_header() << '\n';

        std::cout << "== Header ==" << '\n';
        std::cout << pe.header() << '\n';

        std::cout << "== Optional Header ==" << '\n';
        std::cout << pe.optional_header() << '\n';

        if (const LIEF::PE::RichHeader* rich_header = pe.rich_header()) {
            std::cout << "== Rich Header ==" << '\n';
            std::cout << *rich_header << '\n';
        }

        std::cout << "== Data Directories ==" << '\n';
        for (const LIEF::PE::DataDirectory& directory : pe.data_directories()) {
            std::cout << directory << '\n';
        }

        std::cout << "== Sections ==" << '\n';
        for (const LIEF::PE::Section& section : pe.sections()) {
            std::cout << section << '\n';
        }

        if (pe.imports().size() > 0) {
            std::cout << "== Imports ==" << '\n';
            for (const LIEF::PE::Import& import : pe.imports()) {
                std::cout << import << '\n';
            }
        }

        // if (pe.relocations().size() > 0) {
        //     std::cout << "== Relocations ==" << '\n';
        //     for (const LIEF::PE::Relocation& relocation : pe.relocations()) {
        //         std::cout << relocation << '\n';
        //     }
        // }

        if (const LIEF::PE::TLS* tls = pe.tls()) {
            std::cout << "== TLS ==" << '\n';
            std::cout << *tls << '\n';
        }

        if (const LIEF::PE::Export* exp = pe.get_export()) {
            std::cout << "== Exports ==" << '\n';
            std::cout << *exp << '\n';
        }

        if (!pe.symbols().empty()) {
            std::cout << "== Symbols ==" << '\n';
            for (const LIEF::PE::Symbol& symbol : pe.symbols()) {
                std::cout << symbol << '\n';
            }
        }

        if (pe.has_debug()) {
            std::cout << "== Debug ==" << '\n';
            for (const LIEF::PE::Debug& debug : pe.debug()) {
                std::cout << debug << '\n';
            }
        }

        if (auto manager = pe.resources_manager()) {
            std::cout << "== Resources ==" << '\n';
            std::cout << *manager << '\n';
        }

        for (const LIEF::PE::Signature& sig : pe.signatures()) {
            std::cout << "== Signature ==" << '\n';
            std::cout << sig << '\n';
        }
    }
}
void BinaryMetadata::get_metadata() {}

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