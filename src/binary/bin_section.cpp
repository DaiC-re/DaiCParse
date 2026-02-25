#include "binary/bin_section.hpp"

#include <iomanip>
#include <span>
#include <sstream>
#include <string_view>

#include "binary/binary.hpp"

BinSection::SectionIterator::SectionIterator(const BinSection* section,
                                             bool is_end)
    : _section(section), _content_iter(nullptr) {
    if (section && is_end) {
        _iterating_name = false;
        _name_index = section->name.size();
        _content_iter = section->content.end();
    } else if (section) {
        _content_iter = section->content.begin();
        if (section->name.empty()) {
            _iterating_name = false;
        } else {
            _iterating_name = true;
            _name_index = 0;
        }
    }
}

BinSection::SectionIterator::SectionIterator(const BinSection& section)
    : _section(&section), _content_iter(section.content.begin()) {
    if (!_section || _section->name.empty()) {
        _iterating_name = false;
    } else {
        _iterating_name = true;
        _name_index = 0;
    }
}

BinSection::SectionIterator::reference BinSection::SectionIterator::operator*()
    const {
    if (_iterating_name) {
        return *reinterpret_cast<const uint8_t*>(&_section->name[_name_index]);
    } else {
        return *_content_iter;
    }
}

BinSection::SectionIterator::pointer BinSection::SectionIterator::operator->()
    const {
    if (_iterating_name) {
        return reinterpret_cast<const uint8_t*>(_section->name[_name_index]);
    } else {
        return &(*_content_iter);
    }
}

BinSection::SectionIterator& BinSection::SectionIterator::operator++() {
    if (!_section) return *this;

    if (_iterating_name) {
        _name_index++;
        if (_name_index >= _section->name.size()) {
            _iterating_name = false;
        }
    } else {
        if (_content_iter != _section->content.end()) {
            ++_content_iter;
        }
    }
    return *this;
}

BinSection::SectionIterator BinSection::SectionIterator::operator++(int) {
    SectionIterator temp = *this;
    ++(*this);
    return temp;
}

void BinSection::serialize(std::ostream& out) const {
    uint32_t nameSize = name.size();
    out.write(reinterpret_cast<const char*>(&nameSize), sizeof(nameSize));
    out.write(name.data(), nameSize);

    out.write(reinterpret_cast<const char*>(&offset), sizeof(offset));
    out.write(reinterpret_cast<const char*>(&virtual_addr),
              sizeof(virtual_addr));
    out.write(reinterpret_cast<const char*>(&virtual_size),
              sizeof(virtual_size));

    uint32_t contentSize = content.size();
    out.write(reinterpret_cast<const char*>(&contentSize), sizeof(contentSize));
    std::vector<uint8_t> content_bytes_vec =
        content | std::ranges::to<std::vector<uint8_t>>();
    out.write(reinterpret_cast<const char*>(content_bytes_vec.data()),
              contentSize);
    uint32_t paddingSize = padding.size();
    out.write(reinterpret_cast<const char*>(&paddingSize), sizeof(paddingSize));
    std::vector<uint8_t> padding_bytes_vec =
        padding | std::ranges::to<std::vector<uint8_t>>();
    out.write(reinterpret_cast<const char*>(padding_bytes_vec.data()),
              paddingSize);
}

void BinSection::deserialize(std::istream& in) {
    uint32_t nameSize;
    in.read(reinterpret_cast<char*>(&nameSize), sizeof(nameSize));
    name.resize(nameSize);
    in.read(name.data(), nameSize);

    in.read(reinterpret_cast<char*>(&offset), sizeof(offset));
    in.read(reinterpret_cast<char*>(&virtual_addr), sizeof(virtual_addr));
    in.read(reinterpret_cast<char*>(&virtual_size), sizeof(virtual_size));

    uint32_t contentSize;
    in.read(reinterpret_cast<char*>(&contentSize), sizeof(contentSize));
    // We should allow it to work like if it's from LIEF later, for example with
    // mmap, here the whole section is loaded in memory
    _content_buffer_ptr = new uint8_t[contentSize];
    in.read(reinterpret_cast<char*>(_content_buffer_ptr), contentSize);
    content = LIEF::span<const uint8_t>(_content_buffer_ptr, contentSize);
    // for (auto& c : content) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0')
    //               << static_cast<int>(c) << " ";
    // }

    uint32_t paddingSize;
    in.read(reinterpret_cast<char*>(&paddingSize), sizeof(paddingSize));
    // We should allow it to work like if it's from LIEF later, for example with
    // mmap, here the whole section is loaded in memory
    _padding_buffer_ptr = new uint8_t[paddingSize + 1];
    in.read(reinterpret_cast<char*>(_padding_buffer_ptr), paddingSize);
    padding = LIEF::span<const uint8_t>(_padding_buffer_ptr, paddingSize);
}

BinSection::~BinSection() {
    // In case the content was deserialized
    if (_content_buffer_ptr) {
        // delete _buffer_ptr;
    }
    if (_padding_buffer_ptr) {
        // delete _buffer_ptr;
    }
}
