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

    uint32_t contentSize = content.size();
    out.write(reinterpret_cast<const char*>(&contentSize), sizeof(contentSize));
    std::vector<uint8_t> bytes_vec =
        content | std::ranges::to<std::vector<uint8_t>>();
    out.write(reinterpret_cast<const char*>(bytes_vec.data()), contentSize);
}

void BinSection::deserialize(std::istream& in) {
    uint32_t nameSize;
    in.read(reinterpret_cast<char*>(&nameSize), sizeof(nameSize));
    name.resize(nameSize);
    in.read(name.data(), nameSize);

    uint32_t contentSize;
    in.read(reinterpret_cast<char*>(&contentSize), sizeof(contentSize));
    // We should allow it to work like if it's from LIEF later, for example with
    // mmap, here the whole section is loaded in memory
    _buffer_ptr = new uint8_t[contentSize];
    in.read(reinterpret_cast<char*>(_buffer_ptr), contentSize);
    content = LIEF::span<const uint8_t>(_buffer_ptr, contentSize);
}

BinSection::~BinSection() {
    // In case the content was deserialized
    if (_buffer_ptr) {
        // delete _buffer_ptr;
    }
}
