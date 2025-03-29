#include <iterator>
#include <optional>
#include <ranges>

#include "binary.hpp"

class SectionContentIterator {
   public:
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = uint8_t;  // Iterate over bytes
    using pointer = const uint8_t*;
    using reference = const uint8_t&;

    SectionContentIterator()
        : _sections(std::nullopt),  // Initialize pointer
                                    // members to null
          _sectionIndex(0),
          _byteIndex(0),
          _currentSectionData() {}

    SectionContentIterator(const std::unique_ptr<Binary>& binary,
                           size_t sectionIndex = 0, size_t byteIndex = 0)
        : _sections(binary->_lief_binary->sections()),
          _sectionIndex(sectionIndex),
          _byteIndex(byteIndex) {
        if (_sectionIndex < _sections->size()) {
            _currentSectionData = (*_sections)[_sectionIndex].content();
        } else {
            _currentSectionData = {};  // Empty vector for end iterator
        }
    }

    reference operator*() const { return _currentSectionData[_byteIndex]; }
    pointer operator->() const {
        return const_cast<uint8_t*>(&_currentSectionData[_byteIndex]);
    }

    SectionContentIterator& operator++() {
        ++_byteIndex;
        auto sections = *_sections;
        if (_sectionIndex < sections.size() &&
            _byteIndex >= _currentSectionData.size()) {
            ++_sectionIndex;
            if (_sectionIndex < sections.size()) {
                _currentSectionData = sections[_sectionIndex].content();
                _byteIndex = 0;
            } else {
                _currentSectionData = {};
            }
        }

        return *this;
    }

    SectionContentIterator operator++(int) {
        SectionContentIterator temp = *this;
        ++(*this);
        return temp;
    }

    bool operator==(const SectionContentIterator& other) const {
        return &_sections == &other._sections &&
               _sectionIndex == other._sectionIndex &&
               _byteIndex == other._byteIndex;
    }

    bool operator!=(const SectionContentIterator& other) const {
        return !(*this == other);
    }

   private:
    std::optional<LIEF::Binary::it_sections> _sections;
    size_t _sectionIndex;
    size_t _byteIndex;
    LIEF::span<const uint8_t> _currentSectionData;
};

class SectionContentRange {
   public:
    SectionContentRange(const std::unique_ptr<Binary>& binary)
        : _binary(binary) {}

    SectionContentIterator begin() const {
        return SectionContentIterator(_binary);
    }

    SectionContentIterator end() const {
        return SectionContentIterator(
            _binary, _binary->_lief_binary->sections().size());  // End iterator
    }

   private:
    const std::unique_ptr<Binary>& _binary;
};
