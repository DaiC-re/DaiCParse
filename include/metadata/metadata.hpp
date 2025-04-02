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
    BinaryMetadata(const std::unique_ptr<LIEF::Binary>& binary, std::istream &in);
    BinaryMetadata(const std::unique_ptr<LIEF::Binary>& binary,
                   const std::string& path);
    std::vector<std::pair<std::string, std::string>> get_dos() {
        return this->dos_headers;
    }
    std::vector<ExportedFn> get_exports() { return this->exported_functions; }
    std::vector<std::pair<std::string, std::string>> get_general() {
        return this->general_infos;
    }
    std::vector<ImportedFn> get_imports() { return this->imported_functions; }
    std::vector<std::pair<std::string, std::string>> get_header() {
        return this->file_headers;
    }

    void serialize(std::ostream &out) const;
    void serializePairs(std::vector<std::pair<std::string, std::string>>, std::ostream &out) const;
    void serializeExported(std::vector<ExportedFn>, std::ostream &out) const;
    void serializeImported(std::vector<ImportedFn>, std::ostream &out) const;

    void deserialize(std::istream &in);
    void deserializePairs(std::vector<std::pair<std::string, std::string>> &, std::istream &in);
    void deserializeExported(std::vector<ExportedFn> &, std::istream &in);
    void deserializeImported(std::vector<ImportedFn> &, std::istream &in);

   private:
    void parse_dos();
    void parse_exports();
    void parse_general();
    void parse_header();
    void parse_imports();

   private:
    const std::unique_ptr<LIEF::Binary>& _binary;
    std::vector<ExportedFn> exported_functions;
    std::vector<ImportedFn> imported_functions;
    std::vector<std::pair<std::string, std::string>> general_infos;
    std::vector<std::pair<std::string, std::string>> file_headers;
    std::vector<std::pair<std::string, std::string>> dos_headers;
    std::string _path;
};
