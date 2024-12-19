#pragma once

#include <LIEF/ELF/Binary.hpp>
#include <memory>

class BinaryMetadata {
   public:
    struct ImportedFn {
        unsigned offset;
        std::string file_name;
        std::string fonction_name;
    };
    struct ExportedFn {
        std::string address;
        std::string fonction_name;
    };

   public:
    BinaryMetadata(const std::string &path);
    std::vector<ImportedFn> get_imports();
    std::vector<ExportedFn> get_exports();
    std::vector<std::pair<std::string, std::string>> get_general();
    std::vector<std::pair<std::string, std::string>> get_dos();

   private:
    std::unique_ptr<LIEF::Binary> _binary;
    std::string _path;
};