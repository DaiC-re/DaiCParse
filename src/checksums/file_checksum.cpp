#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "checksums/md5.h"

const std::string compute_md5_from_file(const std::string_view path) {
    std::ifstream file(path.data(), std::ios::binary);
    if (!file) {
        std::cerr << "Unable to open file" << std::endl;
        exit(1);
    }

    // Seek to the end to get the file size
    file.seekg(0, std::ios::end);
    auto file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    char* buffer = new char[file_size];  // Allocate buffer
    std::cout << "file size: " << file_size << std::endl;
    file.read(buffer, file_size);
    if (!file.fail()) {
        std::cout << "File read into buffer successfully!" << std::endl;
    } else {
        std::cerr << "Error reading file!" << std::endl;
        std::cerr << file.fail() << std::endl;
    }
    char signature[MD5_STRING_SIZE] = {};
    auto md5_helper = md5::md5_t(buffer, file_size);
    md5_helper.get_string(signature);

    return std::string(signature, MD5_STRING_SIZE - 1);
}