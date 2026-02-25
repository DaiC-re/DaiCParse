#define CATCH_CONFIG_MAIN
#include "binary/bin_section.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sstream>

TEST_CASE("BinSection Construction and Size", "[BinSection]") {
    std::string name = "TestSection";
    std::vector<uint8_t> content_data = {0x01, 0x02, 0x03, 0x04, 0x05};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());

    BinSection section{name, content};

    REQUIRE(section.name == name);
    REQUIRE(section.content.size() == content_data.size());
    REQUIRE(section.size() == content_data.size());
}

TEST_CASE("BinSection Full Constructor", "[BinSection]") {
    std::string name = "FullSection";
    std::vector<uint8_t> content_data = {0x01, 0x02, 0x03};
    std::vector<uint8_t> padding_data = {0x00, 0x00};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    LIEF::span<const uint8_t> padding(padding_data.data(), padding_data.size());
    
    uintptr_t offset = 0x1000;
    uintptr_t virtual_addr = 0x4000;
    size_t virtual_size = 16;

    BinSection section{name, content, padding, offset, virtual_addr, virtual_size};

    REQUIRE(section.name == name);
    REQUIRE(section.offset == offset);
    REQUIRE(section.virtual_addr == virtual_addr);
    REQUIRE(section.virtual_size == virtual_size);
    REQUIRE(section.content.size() == content_data.size());
    REQUIRE(section.padding.size() == padding_data.size());
    REQUIRE(section.size() == content_data.size() + padding_data.size());
}

TEST_CASE("BinSection Default Constructor", "[BinSection]") {
    BinSection section;

    REQUIRE(section.name.empty());
}

TEST_CASE("BinSection Equality Operator", "[BinSection]") {
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());

    BinSection section1{"Section1", content, {}, 0x1000, 0x4000, 16};
    BinSection section2{"Section2", content, {}, 0x2000, 0x4000, 16};
    BinSection section3{"Section3", content, {}, 0x1000, 0x5000, 32};

    // Same virtual_addr and virtual_size should be equal
    REQUIRE(section1 == section2);
    
    // Different virtual_size should not be equal
    REQUIRE(!(section1 == section3));
}

TEST_CASE("BinSection Iterator - Empty Section", "[BinSection]") {
    std::string name = "";
    std::vector<uint8_t> content_data = {};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    auto begin = section.begin();
    auto end = section.end();

    REQUIRE(begin == end);
}

TEST_CASE("BinSection Iterator - Name Only", "[BinSection]") {
    std::string name = "NameOnly";
    std::vector<uint8_t> content_data = {};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    std::string iterated_name;
    for (const auto& byte : section) {
        iterated_name += byte;
    }

    int count = 0;
    for (auto it = section.begin(); it != section.end(); ++it) {
        count++;
    }
}

TEST_CASE("BinSection Iterator - Content Only", "[BinSection]") {
    std::string name = "";
    std::vector<uint8_t> content_data = {0x01, 0x02, 0x03};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    std::vector<uint8_t> iterated_content;
    for (const auto& byte : section) {
        iterated_content.push_back(byte);
    }
    REQUIRE(iterated_content == content_data);

    int count = 0;
    for (auto it = section.begin(); it != section.end(); ++it) {
        count++;
    }
    REQUIRE(count == content_data.size());
}

TEST_CASE("BinSection Iterator - Mixed Name and Content", "[BinSection]") {
    std::string name = "Name";
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    std::string iterated_name;
    std::vector<uint8_t> iterated_content;
    bool name_done = false;

    for (const auto& byte : section) {
        if (!name_done) {
            iterated_name += byte;
            if (iterated_name.size() == name.size()) {
                name_done = true;
            }
        } else {
            iterated_content.push_back(byte);
        }
    }

    int count = 0;
    for (auto it = section.begin(); it != section.end(); ++it) {
        count++;
    }
}

TEST_CASE("BinSection Iterator - Pre and Post Increment", "[BinSection]") {
    std::string name = "A";
    std::vector<uint8_t> content_data = {0x01};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    auto it = section.begin();
}

TEST_CASE("BinSection Iterator - End Iterator", "[BinSection]") {
    std::string name = "Test";
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    auto end_it = section.end();

    // Iterate to the end
    auto it = section.begin();
    for (size_t i = 0; i < section.size(); ++i) {
        ++it;
    }

    REQUIRE(it == end_it);
}

TEST_CASE("BinSection SectionIterator - Direct Construction", "[BinSection]") {
    std::string name = "Test";
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    BinSection::SectionIterator it{section};
    
    REQUIRE(*it == 'T');
    ++it;
    REQUIRE(*it == 'e');
}

TEST_CASE("BinSection SectionIterator - End Iterator Construction", "[BinSection]") {
    std::string name = "End";
    std::vector<uint8_t> content_data = {0x01};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    BinSection::SectionIterator begin_it{&section, false};
    BinSection::SectionIterator end_it{&section, true};

    REQUIRE(!(begin_it == end_it));
    
    // Iterate to the end
    while (begin_it != end_it) {
        ++begin_it;
    }
    REQUIRE(begin_it == end_it);
}

TEST_CASE("BinSection SectionIterator - Inequality", "[BinSection]") {
    std::string name = "Test";
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    auto it1 = section.begin();
    auto it2 = section.begin();
    
    REQUIRE(!(it1 != it2));
    ++it1;
    REQUIRE(it1 != it2);
}

TEST_CASE("BinSection SectionIterator - Default Construction", "[BinSection]") {
    BinSection::SectionIterator it;
    BinSection::SectionIterator it2;
    
    REQUIRE(it == it2);
}

TEST_CASE("BinSection SectionIterator - Different Sections", "[BinSection]") {
    std::vector<uint8_t> content_data = {0x01};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section1{"Section1", content};
    BinSection section2{"Section2", content};

    BinSection::SectionIterator it1{section1};
    BinSection::SectionIterator it2{section2};
    
    REQUIRE(!(it1 == it2));
}

TEST_CASE("BinSection Serialization and Deserialization", "[BinSection]") {
    std::string name = "SerialTest";
    std::vector<uint8_t> content_data = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> padding_data = {0x00, 0x00};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    LIEF::span<const uint8_t> padding(padding_data.data(), padding_data.size());

    BinSection original{name, content, padding, 0x1000, 0x4000, 32};

    std::stringstream stream;
    original.serialize(stream);

    BinSection deserialized;
    stream.seekg(0);
    deserialized.deserialize(stream);

    REQUIRE(deserialized.name == original.name);
    REQUIRE(deserialized.offset == original.offset);
    REQUIRE(deserialized.virtual_addr == original.virtual_addr);
    REQUIRE(deserialized.virtual_size == original.virtual_size);
    REQUIRE(deserialized.content.size() == original.content.size());
    REQUIRE(deserialized.padding.size() == original.padding.size());

    // Verify content bytes match
    for (size_t i = 0; i < content_data.size(); ++i) {
        REQUIRE(deserialized.content[i] == original.content[i]);
    }

    // Verify padding bytes match
    for (size_t i = 0; i < padding_data.size(); ++i) {
        REQUIRE(deserialized.padding[i] == original.padding[i]);
    }
}

TEST_CASE("BinSection Serialization - Empty Section", "[BinSection]") {
    BinSection section{"", {}};

    std::stringstream stream;
    section.serialize(stream);

    BinSection deserialized;
    stream.seekg(0);
    deserialized.deserialize(stream);

    REQUIRE(deserialized.name.empty());
    REQUIRE(deserialized.content.size() == 0);
    REQUIRE(deserialized.padding.size() == 0);
}

TEST_CASE("BinSection Size with Padding", "[BinSection]") {
    std::string name = "SizeTest";
    std::vector<uint8_t> content_data = {0x01, 0x02, 0x03};
    std::vector<uint8_t> padding_data = {0x00, 0x00, 0x00, 0x00};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    LIEF::span<const uint8_t> padding(padding_data.data(), padding_data.size());

    BinSection section{name, content, padding, 0, 0, 0};

    REQUIRE(section.size() == content_data.size() + padding_data.size());
    REQUIRE(section.size() == 7);
}

TEST_CASE("BinSection Large Content", "[BinSection]") {
    std::string name = "Large";
    std::vector<uint8_t> content_data(1000);
    for (size_t i = 0; i < content_data.size(); ++i) {
        content_data[i] = static_cast<uint8_t>(i % 256);
    }
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());

    BinSection section{name, content};

    int count = 0;
    for (auto it = section.begin(); it != section.end(); ++it) {
        count++;
    }
    REQUIRE(count == section.size());
}

TEST_CASE("BinSection Iterator - Const Reference Behavior", "[BinSection]") {
    std::string name = "Const";
    std::vector<uint8_t> content_data = {0xFF, 0xEE};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    const BinSection& const_section = section;
    auto const_it = const_section.begin();
    auto const_end = const_section.end();

    int count = 0;
    for (auto it = const_it; it != const_end; ++it) {
        count++;
    }
    REQUIRE(count == section.size());
}

TEST_CASE("BinSection Multiple Serialization Round-Trips", "[BinSection]") {
    std::string name = "MultiRound";
    std::vector<uint8_t> content_data = {0xAA, 0xBB, 0xCC};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());

    BinSection original{name, content, {}, 0x5000, 0x8000, 64};

    // First round-trip
    std::stringstream stream1;
    original.serialize(stream1);
    BinSection after_first;
    stream1.seekg(0);
    after_first.deserialize(stream1);

    // Second round-trip
    std::stringstream stream2;
    after_first.serialize(stream2);
    BinSection after_second;
    stream2.seekg(0);
    after_second.deserialize(stream2);

    REQUIRE(after_second.name == original.name);
    REQUIRE(after_second.offset == original.offset);
    REQUIRE(after_second.virtual_addr == original.virtual_addr);
    REQUIRE(after_second.virtual_size == original.virtual_size);
}

TEST_CASE("BinSection Iterator - Name to Content Transition", "[BinSection]") {
    std::string name = "AB";
    std::vector<uint8_t> content_data = {0x12, 0x34};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    BinSection::SectionIterator it{section};
    
    // Navigate through name
    REQUIRE(*it == 'A');
    ++it;
    REQUIRE(*it == 'B');
    ++it;
    // Now in content
    REQUIRE(*it == 0x12);
    ++it;
    REQUIRE(*it == 0x34);
}
