#pragma once
#include <LIEF/ELF/Binary.hpp>
#include <string>

#include "metadata/metadata.hpp"

class Binary {
    friend class SectionContentIterator;
    friend class SectionContentRange;

   public:
    Binary(const std::string path);
    ~Binary();
    void get_bytes();

    struct Section {
        std::string name;
        std::string content;
    };

   public:
    std::unique_ptr<BinaryMetadata> metadata;
    std::vector<Section> sections;

   private:
    std::unique_ptr<LIEF::Binary> _lief_binary;
};