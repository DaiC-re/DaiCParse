#pragma once

#include <LIEF/span.hpp>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

struct BinSection {
    std::string name;
    uintptr_t offset;
    LIEF::span<const uint8_t> content;
    uintptr_t virtual_addr;
    void serialize(std::ostream& out) const;
    void deserialize(std::istream& in);
    class SectionIterator;
    BinSection(std::string name, LIEF::span<const uint8_t> content,
               uintptr_t offset, uintptr_t virtual_addr)
        : name(name),
          content(content),
          offset(offset),
          virtual_addr(virtual_addr) {}
    BinSection() = default;
    ~BinSection();

   private:
    uint8_t* _buffer_ptr = nullptr;

   public:
    using iterator = decltype(content)::iterator;
    using const_iterator = decltype(content)::iterator;
    using value_type = uint8_t;
    using reference = const uint8_t&;
    using const_reference = const uint8_t&;

    iterator begin() { return content.begin(); }
    iterator end() { return content.end(); }
    const_iterator begin() const { return content.begin(); }
    const_iterator end() const { return content.end(); }

    class SectionIterator {
       public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = uint8_t;
        using difference_type = std::ptrdiff_t;
        using pointer = const uint8_t*;
        using reference = const uint8_t&;

       protected:
        const BinSection* _section = nullptr;
        bool _iterating_name = true;
        std::size_t _name_index = 0;
        LIEF::span<const uint8_t>::iterator _content_iter;

       public:
        SectionIterator() = default;

        explicit SectionIterator(const BinSection& section);

        SectionIterator(const BinSection* section, bool is_end);

        reference operator*() const;

        pointer operator->() const;

        SectionIterator& operator++();

        SectionIterator operator++(int);

        friend inline bool operator==(const SectionIterator& lhs,
                                      const SectionIterator& rhs);

        friend inline bool operator!=(const SectionIterator& lhs,
                                      const SectionIterator& rhs);
    };

    // inline BinSection::iterator begin() const { return
    // SectionIterator(*this); }

    // inline BinSection::iterator end() const {
    //     return SectionIterator(this, true);
    // }

    inline std::size_t size() const { return name.size() + content.size(); }
};

inline bool operator==(const BinSection::SectionIterator& lhs,
                       const BinSection::SectionIterator& rhs) {
    if (lhs._section != rhs._section) {
        return false;
    }
    if (!lhs._section) {
        return true;
    }

    if (lhs._iterating_name != rhs._iterating_name) {
        return false;
    }

    if (lhs._iterating_name) {
        return lhs._name_index == rhs._name_index;
    } else {
        return lhs._content_iter == rhs._content_iter;
    }
}

inline bool operator!=(const BinSection::SectionIterator& lhs,
                       const BinSection::SectionIterator& rhs) {
    return !(lhs == rhs);
}
