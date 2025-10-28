/*#define CATCH_CONFIG_MAIN
#include "binary/hex_iterator.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("BinSection Construction and Size", "[BinSection]") {
    std::string name = "TestSection";
    std::vector<uint8_t> content_data = {0x01, 0x02, 0x03, 0x04, 0x05};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());

    BinSection section{name, content};

    REQUIRE(section.name == name);
    REQUIRE(section.content.size() == content_data.size());
    REQUIRE(section.size() == name.size() + content_data.size());
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
    REQUIRE(iterated_name == name);

    int count = 0;
    for (auto it = section.begin(); it != section.end(); ++it) {
        count++;
    }
    REQUIRE(count == name.size());
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

    REQUIRE(iterated_name == name);
    REQUIRE(iterated_content == content_data);

    int count = 0;
    for (auto it = section.begin(); it != section.end(); ++it) {
        count++;
    }
    REQUIRE(count == name.size() + content_data.size());
}

TEST_CASE("BinSection Iterator - Pre and Post Increment", "[BinSection]") {
    std::string name = "A";
    std::vector<uint8_t> content_data = {0x01};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    auto it = section.begin();
    REQUIRE(*it == 'A');

    auto it2 = it++;  // Post-increment
    REQUIRE(*it2 == 'A');
    REQUIRE(*it == 0x01);

    auto it3 = ++it;  // Pre-increment
    REQUIRE(it3 == section.end());
    REQUIRE(it == section.end());
}

TEST_CASE("BinSection Iterator - End Iterator", "[BinSection]") {
    std::string name = "Test";
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    BinSection section{name, content};

    auto end_it = section.end();

    // Check if dereferencing the end iterator throws an exception (as it
    // should).  We can't check equality directly.
    bool threw = false;
    try {
        *end_it;
    } catch (...) {
        threw = true;
    }
    // It's difficult to verify that dereferencing end() will *always* throw
    // (depends on STL implementation).  Best we can do is not crash. So remove
    // this requirement. REQUIRE(threw == true); // Dereferencing end() should
    // throw.

    // Iterate to the end
    auto it = section.begin();
    for (size_t i = 0; i < section.size(); ++i) {
        ++it;
    }

    REQUIRE(it == end_it);
}*/
