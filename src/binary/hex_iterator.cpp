#include "binary/hex_iterator.hpp"

#include <iomanip>
#include <span>
#include <sstream>
#include <string_view>

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
