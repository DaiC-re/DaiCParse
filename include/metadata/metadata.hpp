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
    BinaryMetadata(std::unique_ptr<LIEF::Binary> &binary);

   private:
    void parse_imports();
    void parse_exports();
    void parse_general();
    void parse_dos();
    void parse_header();

   public:
    std::vector<ExportedFn> exported_functions;
    std::vector<ImportedFn> imported_functions;
    std::vector<std::pair<std::string, std::string>> general_infos;
    std::vector<std::pair<std::string, std::string>> file_headers;
    std::vector<std::pair<std::string, std::string>> dos_headers;
    std::string _path;

   private:
    std::unique_ptr<LIEF::Binary> &_binary;
};