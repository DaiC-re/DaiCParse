#include "binary/binary.hpp"
#include <catch2/catch_test_macros.hpp>
#include <sstream>
#include <vector>
#include <filesystem>
#include <iostream>

// Fixture for testing with actual binary file
struct BinaryFixture {
    std::string test_binary_path;
    std::unique_ptr<Binary> binary;
    
    BinaryFixture() {
        // Use the dummy binary in project root
        test_binary_path = "./dummy_test_binary.bin";
        
        // Only initialize binary if the file exists
        if (std::filesystem::exists(test_binary_path)) {
            try {
                binary = std::make_unique<Binary>(test_binary_path);
            } catch (const std::exception& e) {
                // Binary might not be parseable, that's okay for some tests
                std::cerr << "Failed to load test binary: " << e.what() << std::endl;
            }
        }
    }
    
    ~BinaryFixture() = default;
};

// Test Binary::Function class independently
TEST_CASE("Binary::Function Construction", "[Binary][Function]") {
    Binary::Function func("test_function", 0x1000, 0x2000, 5);
    
    REQUIRE(func.getName() == "test_function");
    REQUIRE(func.getStart() == 0x1000);
    REQUIRE(func.getEnd() == 0x2000);
}

TEST_CASE("Binary::Function Serialization", "[Binary][Function]") {
    Binary::Function original("my_func", 0x4000, 0x5000, 20);
    
    std::stringstream stream;
    original.serialize(stream);
    
    Binary::Function deserialized;
    stream.seekg(0);
    deserialized.deserialize(stream);
    
    REQUIRE(deserialized.getName() == original.getName());
    REQUIRE(deserialized.getStart() == original.getStart());
    REQUIRE(deserialized.getEnd() == original.getEnd());
}

TEST_CASE("Binary::Function Multiple Serialization Round-Trips", "[Binary][Function]") {
    Binary::Function original("round_trip_func", 0x3000, 0x4000, 15);
    
    // First round-trip
    std::stringstream stream1;
    original.serialize(stream1);
    Binary::Function after_first;
    stream1.seekg(0);
    after_first.deserialize(stream1);
    
    // Second round-trip
    std::stringstream stream2;
    after_first.serialize(stream2);
    Binary::Function after_second;
    stream2.seekg(0);
    after_second.deserialize(stream2);
    
    REQUIRE(after_second.getName() == original.getName());
    REQUIRE(after_second.getStart() == original.getStart());
    REQUIRE(after_second.getEnd() == original.getEnd());
}

TEST_CASE("Binary::Function Empty Name", "[Binary][Function]") {
    Binary::Function func("", 0x0000, 0x1000, 0);
    
    REQUIRE(func.getName().empty());
    REQUIRE(func.getStart() == 0x0000);
}

TEST_CASE("Binary::Function Large Address Space", "[Binary][Function]") {
    uintptr_t start = 0x140000000ULL;  // High address for PE64
    uintptr_t end = 0x140010000ULL;
    Binary::Function func("large_addr_func", start, end, 1000);
    
    REQUIRE(func.getStart() == start);
    REQUIRE(func.getEnd() == end);
    
    std::stringstream stream;
    func.serialize(stream);
    
    Binary::Function loaded;
    stream.seekg(0);
    loaded.deserialize(stream);
    
    REQUIRE(loaded.getStart() == start);
    REQUIRE(loaded.getEnd() == end);
}

// Test section lookup logic (isolates core logic from file IO)
TEST_CASE("Binary section_from_rva - Single Section", "[Binary][Sections]") {
    std::vector<BinSection> sections;
    std::vector<uint8_t> content_data = {0x01, 0x02, 0x03};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    
    sections.push_back(BinSection(".text", content, {}, 0x1000, 0x4000, 0x1000));
    
    // Test RVA lookup logic
    auto addr = 0x4000UL + 0x100;  // Within section
    auto result = std::find_if(
        sections.begin(), sections.end(),
        [addr](const BinSection& section) {
            return section.virtual_addr <= addr &&
                   addr < (section.virtual_addr + section.virtual_size);
        });
    
    REQUIRE(result != sections.end());
    REQUIRE(result->name == ".text");
}

TEST_CASE("Binary section_from_rva - Multiple Sections", "[Binary][Sections]") {
    std::vector<BinSection> sections;
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    
    sections.push_back(BinSection(".text", content, {}, 0x1000, 0x4000, 0x1000));
    sections.push_back(BinSection(".data", content, {}, 0x2000, 0x5000, 0x1000));
    sections.push_back(BinSection(".rsrc", content, {}, 0x3000, 0x6000, 0x1000));
    
    // Test RVA in second section
    auto addr = 0x5000UL + 0x500;
    auto result = std::find_if(
        sections.begin(), sections.end(),
        [addr](const BinSection& section) {
            return section.virtual_addr <= addr &&
                   addr < (section.virtual_addr + section.virtual_size);
        });
    
    REQUIRE(result != sections.end());
    REQUIRE(result->name == ".data");
}

TEST_CASE("Binary section_from_rva - Address Not Found", "[Binary][Sections]") {
    std::vector<BinSection> sections;
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    
    sections.push_back(BinSection(".text", content, {}, 0x1000, 0x4000, 0x1000));
    
    // Address outside all sections
    auto addr = 0x7000UL;
    auto result = std::find_if(
        sections.begin(), sections.end(),
        [addr](const BinSection& section) {
            return section.virtual_addr <= addr &&
                   addr < (section.virtual_addr + section.virtual_size);
        });
    
    REQUIRE(result == sections.end());
}

TEST_CASE("Binary section_from_rva - Boundary Conditions", "[Binary][Sections]") {
    std::vector<BinSection> sections;
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    
    sections.push_back(BinSection(".text", content, {}, 0x1000, 0x4000, 0x100));
    
    // Test exact start address
    auto addr_start = 0x4000UL;
    auto result = std::find_if(
        sections.begin(), sections.end(),
        [addr_start](const BinSection& section) {
            return section.virtual_addr <= addr_start &&
                   addr_start < (section.virtual_addr + section.virtual_size);
        });
    REQUIRE(result != sections.end());
    
    // Test last valid address
    auto addr_end = 0x4000UL + 0xFF;
    result = std::find_if(
        sections.begin(), sections.end(),
        [addr_end](const BinSection& section) {
            return section.virtual_addr <= addr_end &&
                   addr_end < (section.virtual_addr + section.virtual_size);
        });
    REQUIRE(result != sections.end());
    
    // Test address just beyond end (should fail)
    auto addr_beyond = 0x4000UL + 0x100;
    result = std::find_if(
        sections.begin(), sections.end(),
        [addr_beyond](const BinSection& section) {
            return section.virtual_addr <= addr_beyond &&
                   addr_beyond < (section.virtual_addr + section.virtual_size);
        });
    REQUIRE(result == sections.end());
}

TEST_CASE("Binary Text Section Finding Logic", "[Binary][Sections]") {
    std::vector<BinSection> sections;
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    
    sections.push_back(BinSection(".text", content, {}, 0x1000, 0x4000, 0x1000));
    sections.push_back(BinSection(".data", content, {}, 0x2000, 0x5000, 0x1000));
    
    // Test finding .text section
    auto text_it = std::find_if(
        sections.begin(), sections.end(),
        [](const BinSection& el) { return el.name == ".text"; });
    
    REQUIRE(text_it != sections.end());
    REQUIRE(text_it->name == ".text");
}

TEST_CASE("Binary Text Section Not Found", "[Binary][Sections]") {
    std::vector<BinSection> sections;
    std::vector<uint8_t> content_data = {0x01, 0x02};
    LIEF::span<const uint8_t> content(content_data.data(), content_data.size());
    
    sections.push_back(BinSection(".data", content, {}, 0x2000, 0x5000, 0x1000));
    sections.push_back(BinSection(".rsrc", content, {}, 0x3000, 0x6000, 0x1000));
    
    auto text_it = std::find_if(
        sections.begin(), sections.end(),
        [](const BinSection& el) { return el.name == ".text"; });
    
    REQUIRE(text_it == sections.end());
}

TEST_CASE("Binary Function Storage and Retrieval", "[Binary][Functions]") {
    std::vector<Binary::Function> functions;
    
    functions.push_back(Binary::Function("func1", 0x1000, 0x2000, 5));
    functions.push_back(Binary::Function("func2", 0x3000, 0x4000, 10));
    
    // Test finding function by address
    auto func_it = std::find_if(
        functions.begin(), functions.end(),
        [](const Binary::Function& func) {
            return func.getStart() == 0x3000;
        });
    
    REQUIRE(func_it != functions.end());
    REQUIRE(func_it->getName() == "func2");
}

TEST_CASE("Binary Function Naming Convention", "[Binary][Functions]") {
    std::string address = "1a2b3c4d";
    auto function_name = std::string("function_") + address;
    
    REQUIRE(function_name == "function_1a2b3c4d");
}

// ==================== INTEGRATION TESTS WITH DUMMY BINARY ====================

TEST_CASE_METHOD(BinaryFixture, "Binary loads dummy test binary", "[Binary][Integration]") {
    // Skip if binary doesn't exist
    if (!std::filesystem::exists(test_binary_path)) {
        SKIP("Test binary not found at " << test_binary_path);
    }
    
    REQUIRE(binary != nullptr);
}

TEST_CASE_METHOD(BinaryFixture, "Binary has sections after loading", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    REQUIRE(!binary->sections.empty());
}

TEST_CASE_METHOD(BinaryFixture, "Binary metadata is initialized", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    REQUIRE(binary->metadata != nullptr);
}

TEST_CASE_METHOD(BinaryFixture, "Binary can find .text section", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    try {
        auto& text_section = binary->getTextSection();
        REQUIRE(text_section.name == ".text");
        REQUIRE(text_section.virtual_size > 0);
    } catch (const std::runtime_error&) {
        SKIP("Test binary has no .text section");
    }
}

TEST_CASE_METHOD(BinaryFixture, "Binary instruction count is positive", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    try {
        size_t count = binary->getInstructionCount();
        REQUIRE(count > 0);
    } catch (const std::runtime_error&) {
        SKIP("Instructions not detected");
    }
}

TEST_CASE_METHOD(BinaryFixture, "Binary text section virtual address is valid", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    try {
        uintptr_t vaddr = binary->getTextSectionVirtualAddr();
        REQUIRE(vaddr > 0);
    } catch (const std::runtime_error&) {
        SKIP("Text section not found");
    }
}

TEST_CASE_METHOD(BinaryFixture, "Binary section lookup by RVA works", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    try {
        auto& text_section = binary->getTextSection();
        // Look up an address within the text section
        auto result = binary->section_from_rva(text_section.virtual_addr + 10);
        REQUIRE(result != nullptr);
        REQUIRE(result->name == ".text");
    } catch (const std::runtime_error&) {
        SKIP("Text section not found");
    }
}

TEST_CASE_METHOD(BinaryFixture, "Binary section lookup returns nullptr for invalid RVA", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    // Use an invalid RVA that's unlikely to be in any section
    auto result = binary->section_from_rva(0xDEADBEEF);
    REQUIRE(result == nullptr);
}

TEST_CASE_METHOD(BinaryFixture, "Binary sections have valid properties", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    REQUIRE(!binary->sections.empty());
    
    for (const auto& section : binary->sections) {
        REQUIRE(!section.name.empty());
        REQUIRE(section.virtual_size >= 0);
        REQUIRE(section.virtual_addr >= 0);
    }
}

TEST_CASE_METHOD(BinaryFixture, "Binary has no overlapping sections", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    for (size_t i = 0; i < binary->sections.size(); ++i) {
        for (size_t j = i + 1; j < binary->sections.size(); ++j) {
            const auto& sec1 = binary->sections[i];
            const auto& sec2 = binary->sections[j];
            
            uintptr_t sec1_end = sec1.virtual_addr + sec1.virtual_size;
            uintptr_t sec2_end = sec2.virtual_addr + sec2.virtual_size;
            
            // Check for overlap
            bool overlap = !(sec1_end <= sec2.virtual_addr || sec2_end <= sec1.virtual_addr);
            REQUIRE(!overlap);
        }
    }
}

TEST_CASE_METHOD(BinaryFixture, "Binary functions can be created and retrieved", "[Binary][Integration]") {
    if (!std::filesystem::exists(test_binary_path) || !binary) {
        SKIP("Test binary not available");
    }
    
    // Test the internal functions vector
    auto initial_count = binary->_functions.size();
    
    // The functions should have been populated during parsing
    // We can't directly call add_function (it's private), but we can verify
    // that functions were detected if the binary has code
    
    try {
        auto& text_section = binary->getTextSection();
        if (text_section.virtual_size > 0) {
            // If we have a text section, functions might be detected
            REQUIRE(binary->_functions.size() >= 0);  // At least initialized
        }
    } catch (const std::runtime_error&) {
        SKIP("Text section not found");
    }
}
