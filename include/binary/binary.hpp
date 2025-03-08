#pragma once
#include <LIEF/ELF/Binary.hpp>
#include <string>

#include "metadata/metadata.hpp"

class Binary {
   public:
    Binary() {};
    Binary(std::istream &in);
    Binary(const std::string path);
    ~Binary();
    void get_bytes();

    struct Section {
        std::string name;
        std::string content;

        void serialize(std::ostream &out) const;
        void deserialize(std::istream &in);
    };

   public:
    std::unique_ptr<BinaryMetadata> metadata;
    std::vector<Section> sections;

   private:
    std::unique_ptr<LIEF::Binary> _lief_binary;
};
