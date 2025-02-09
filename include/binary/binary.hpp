#pragma once
#include <LIEF/ELF/Binary.hpp>
#include <string>

#include "metadata/metadata.hpp"

class Binary {
   public:
    Binary(const std::string path);
    ~Binary();
    void get_bytes();

   public:
    std::unique_ptr<BinaryMetadata> _metadata;

   private:
    std::unique_ptr<LIEF::Binary> _lief_binary;
};