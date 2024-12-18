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

   public:
    BinaryMetadata(std::unique_ptr<LIEF::Binary> &binary);
    void get_metadata();
    std::vector<ImportedFn> get_imports();

   private:
    std::unique_ptr<LIEF::Binary> &_binary;
};