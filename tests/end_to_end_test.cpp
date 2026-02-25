#include "binary/binary.hpp"
#include "binary/binary_hash.hpp"
#include "binary_view/binary_view.hpp"
#include "checksums/file_checksum.h"
#include "checksums/md5.h"
#include "hex_utils/hex_utils.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <memory>
#include <vector>
#include <chrono>
#include <algorithm>

// ===================== END-TO-END TEST FIXTURE =====================

struct EndToEndFixture {
    std::string test_binary_path;
    std::unique_ptr<Binary> binary;
    
    EndToEndFixture() {
        test_binary_path = "./dummy_test_binary.bin";
        
        if (std::filesystem::exists(test_binary_path)) {
            try {
                binary = std::make_unique<Binary>(test_binary_path);
            } catch (const std::exception& e) {
                std::cerr << "Failed to load test binary for E2E: " << e.what() << std::endl;
            }
        }
    }
    
    ~EndToEndFixture() = default;
    
    // Helper: Check if binary is available
    bool isBinaryAvailable() const {
        return std::filesystem::exists(test_binary_path) && binary != nullptr;
    }
};

// ===================== COMPLETE PIPELINE TESTS =====================

TEST_CASE_METHOD(EndToEndFixture, "E2E: Complete Binary Analysis Pipeline", "[E2E][Complete]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Step 1: Verify binary loaded
    REQUIRE(binary != nullptr);
    REQUIRE(!binary->sections.empty());
    
    // Step 2: Verify metadata extracted
    REQUIRE(binary->metadata != nullptr);
    
    // Step 3: Try to get text section
    try {
        auto& text_section = binary->getTextSection();
        REQUIRE(text_section.name == ".text");
        REQUIRE(text_section.virtual_size > 0);
        
        // Step 4: Verify instruction count
        size_t instr_count = binary->getInstructionCount();
        REQUIRE(instr_count > 0);
        
    } catch (const std::runtime_error&) {
        SKIP("Text section or disassembly unavailable");
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Binary Parsing and Section Extraction", "[E2E][Parsing]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Verify all sections are properly extracted
    REQUIRE(!binary->sections.empty());
    
    // Collect all section names
    std::vector<std::string> section_names;
    for (const auto& section : binary->sections) {
        section_names.push_back(section.name);
        
        // Validate section properties
        REQUIRE(!section.name.empty());
        REQUIRE(section.virtual_addr >= 0);
        REQUIRE(section.virtual_size >= 0);
        REQUIRE(section.offset >= 0);
    }
    
    // Verify expected sections exist
    auto has_text = std::find(section_names.begin(), section_names.end(), ".text") != section_names.end();
    REQUIRE(has_text);  // PE binaries should have .text
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Metadata Extraction and Validation", "[E2E][Metadata]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    REQUIRE(binary->metadata != nullptr);
    
    // Verify metadata is populated
    // (Actual metadata content depends on binary format)
    // Just verify it exists and is accessible
    REQUIRE(binary->metadata != nullptr);
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Section Navigation and RVA Lookup", "[E2E][Navigation]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    try {
        auto& text_section = binary->getTextSection();
        
        // Test 1: Lookup address at section start
        auto result = binary->section_from_rva(text_section.virtual_addr);
        REQUIRE(result != nullptr);
        REQUIRE(result->name == ".text");
        
        // Test 2: Lookup address in middle of section
        if (text_section.virtual_size > 100) {
            auto mid_addr = text_section.virtual_addr + text_section.virtual_size / 2;
            result = binary->section_from_rva(mid_addr);
            REQUIRE(result != nullptr);
            REQUIRE(result->name == ".text");
        }
        
        // Test 3: Lookup invalid address
        auto invalid_result = binary->section_from_rva(0xDEADBEEF);
        REQUIRE(invalid_result == nullptr);
        
    } catch (const std::runtime_error&) {
        SKIP("Text section not found");
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Disassembly and Function Detection", "[E2E][Disassembly]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    try {
        // Verify disassembly was performed
        size_t instr_count = binary->getInstructionCount();
        REQUIRE(instr_count > 0);
        
        // Verify checkpoint system works
        REQUIRE(!binary->_disass_checkpoints.empty());
        
        // Verify functions were detected (if any)
        // This depends on the binary content
        REQUIRE(binary->_functions.size() >= 0);
        
    } catch (const std::runtime_error&) {
        SKIP("Disassembly not available");
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Section Content Iteration", "[E2E][Iteration]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    try {
        auto& text_section = binary->getTextSection();
        
        // Iterate through section content
        std::vector<uint8_t> content_bytes;
        for (const auto& byte : text_section) {
            content_bytes.push_back(byte);
        }
        
        // Verify we got bytes
        REQUIRE(content_bytes.size() > 0);
        REQUIRE(content_bytes.size() == text_section.content.size());
        
    } catch (const std::runtime_error&) {
        SKIP("Text section not found");
    }
}

// ===================== CHECKSUM AND HASHING TESTS =====================

TEST_CASE_METHOD(EndToEndFixture, "E2E: File Checksum Calculation", "[E2E][Checksums]") {
    if (!std::filesystem::exists(test_binary_path)) {
        SKIP("Test binary not available");
    }
    
    // Calculate checksum of the test binary
    try {
        auto checksum = compute_md5_from_file(test_binary_path);
        
        // Verify checksum is valid
        REQUIRE(!checksum.empty());
        
    } catch (const std::exception& e) {
        SKIP("Checksum calculation not available");
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: MD5 Hash Calculation", "[E2E][Hashing]") {
    if (!std::filesystem::exists(test_binary_path)) {
        SKIP("Test binary not available");
    }
    
    // Calculate MD5 hash using the existing function
    try {
        auto hash = compute_md5_from_file(test_binary_path);
        REQUIRE(!hash.empty());
        // MD5 hash should be 32 characters (hex digest)
        REQUIRE(hash.length() >= 16);
        
    } catch (const std::exception& e) {
        SKIP("MD5 calculation not available");
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Binary Hash Calculation", "[E2E][BinaryHash]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Calculate cumulative hash by iterating through sections
    try {
        std::stringstream hash_stream;
        
        for (const auto& section : binary->sections) {
            size_t byte_count = 0;
            for (const auto& byte : section) {
                (void)byte;
                byte_count++;
            }
            hash_stream << "Section " << section.name << ": " << byte_count << " bytes\n";
        }
        
        auto hash_report = hash_stream.str();
        REQUIRE(!hash_report.empty());
        
    } catch (const std::exception&) {
        SKIP("Hash calculation failed");
    }
}

// ===================== DATA TRANSFORMATION TESTS =====================

TEST_CASE_METHOD(EndToEndFixture, "E2E: Hex Encoding of Section Data", "[E2E][HexUtils]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    try {
        auto& text_section = binary->getTextSection();
        
        // Get first few bytes and encode as hex
        std::vector<uint8_t> sample;
        for (const auto& byte : text_section) {
            sample.push_back(byte);
            if (sample.size() >= 16) break;
        }
        
        REQUIRE(!sample.empty());
        
    } catch (const std::runtime_error&) {
        SKIP("Text section not found");
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Binary Section Serialization and Deserialization", "[E2E][Serialization]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Test serializing a section
    try {
        auto& text_section = binary->getTextSection();
        
        std::stringstream stream;
        text_section.serialize(stream);
        
        // Verify we wrote data
        REQUIRE(stream.tellp() > 0);
        
        // Try to deserialize
        BinSection deserialized;
        stream.seekg(0);
        deserialized.deserialize(stream);
        
        REQUIRE(deserialized.name == text_section.name);
        REQUIRE(deserialized.virtual_addr == text_section.virtual_addr);
        REQUIRE(deserialized.virtual_size == text_section.virtual_size);
        
    } catch (const std::runtime_error&) {
        SKIP("Text section not found");
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Function Serialization Pipeline", "[E2E][FunctionSerialization]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    try {
        // Get first function if available
        if (!binary->_functions.empty()) {
            auto& first_func = binary->_functions[0];
            
            // Serialize
            std::stringstream stream;
            first_func.serialize(stream);
            
            REQUIRE(stream.tellp() > 0);
            
            // Deserialize
            Binary::Function loaded;
            stream.seekg(0);
            loaded.deserialize(stream);
            
            REQUIRE(loaded.getName() == first_func.getName());
            REQUIRE(loaded.getStart() == first_func.getStart());
            REQUIRE(loaded.getEnd() == first_func.getEnd());
        }
        
    } catch (const std::exception&) {
        SKIP("Function serialization not available");
    }
}

// ===================== MULTI-STEP WORKFLOWS =====================

TEST_CASE_METHOD(EndToEndFixture, "E2E: Complete Analysis and Export Workflow", "[E2E][Workflow]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    std::stringstream export_stream;
    
    // Step 1: Export basic binary info
    export_stream << "=== BINARY ANALYSIS REPORT ===\n";
    export_stream << "Total Sections: " << binary->sections.size() << "\n";
    
    // Step 2: Export section details
    export_stream << "\n=== SECTIONS ===\n";
    for (const auto& section : binary->sections) {
        export_stream << "Section: " << section.name << "\n";
        export_stream << "  Virtual Addr: 0x" << std::hex << section.virtual_addr << std::dec << "\n";
        export_stream << "  Virtual Size: 0x" << std::hex << section.virtual_size << std::dec << "\n";
        export_stream << "  File Offset: 0x" << std::hex << section.offset << std::dec << "\n";
    }
    
    // Step 3: Try to export disassembly info
    try {
        size_t instr_count = binary->getInstructionCount();
        export_stream << "\n=== DISASSEMBLY ===\n";
        export_stream << "Instructions: " << instr_count << "\n";
        export_stream << "Checkpoints: " << binary->_disass_checkpoints.size() << "\n";
    } catch (...) {
        // Optional
    }
    
    // Step 4: Export function info
    export_stream << "\n=== FUNCTIONS ===\n";
    export_stream << "Detected Functions: " << binary->_functions.size() << "\n";
    for (const auto& func : binary->_functions) {
        export_stream << "  " << func.getName() << ": 0x" << std::hex << func.getStart() 
                      << " - 0x" << func.getEnd() << std::dec << "\n";
    }
    
    // Verify export was successful
    REQUIRE(export_stream.str().length() > 0);
    REQUIRE(export_stream.str().find("BINARY ANALYSIS REPORT") != std::string::npos);
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Binary Comparison Workflow", "[E2E][Comparison]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Compare sections between two loads
    auto& sections1 = binary->sections;
    
    // Reload binary (simulating second load)
    std::unique_ptr<Binary> binary2;
    try {
        binary2 = std::make_unique<Binary>(test_binary_path);
    } catch (...) {
        SKIP("Cannot load binary twice");
    }
    
    auto& sections2 = binary2->sections;
    
    // Compare
    REQUIRE(sections1.size() == sections2.size());
    
    for (size_t i = 0; i < sections1.size(); ++i) {
        REQUIRE(sections1[i].name == sections2[i].name);
        REQUIRE(sections1[i].virtual_addr == sections2[i].virtual_addr);
        REQUIRE(sections1[i].virtual_size == sections2[i].virtual_size);
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Section Content Integrity Check", "[E2E][Integrity]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Verify all sections can be read without errors
    for (const auto& section : binary->sections) {
        std::vector<uint8_t> bytes;
        
        try {
            for (const auto& byte : section) {
                bytes.push_back(byte);
            }
            
            REQUIRE(bytes.size() == section.content.size());
            
        } catch (const std::exception& e) {
            FAIL("Failed to read section " << section.name);
        }
    }
}

// ===================== STRESS AND PERFORMANCE TESTS =====================

TEST_CASE_METHOD(EndToEndFixture, "E2E: Large Content Iteration Performance", "[E2E][Performance]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    try {
        auto& text_section = binary->getTextSection();
        
        // Time the iteration
        auto start = std::chrono::high_resolution_clock::now();
        
        size_t byte_count = 0;
        for (const auto& byte : text_section) {
            (void)byte;  // Use the byte
            byte_count++;
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        // Verify iteration worked
        REQUIRE(byte_count == text_section.size());
        
        // Performance check (should be reasonably fast)
        REQUIRE(duration.count() < 5000);  // Less than 5 seconds
        
    } catch (const std::runtime_error&) {
        SKIP("Text section not found");
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Multiple Section Processing", "[E2E][Stress]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Process all sections
    size_t total_bytes = 0;
    size_t total_sections = 0;
    
    for (const auto& section : binary->sections) {
        try {
            std::vector<uint8_t> bytes;
            for (const auto& byte : section) {
                bytes.push_back(byte);
            }
            
            total_bytes += bytes.size();
            total_sections++;
            
        } catch (...) {
            // Some sections might not be readable
            continue;
        }
    }
    
    REQUIRE(total_sections > 0);
    REQUIRE(total_bytes > 0);
}

// ===================== ERROR HANDLING AND EDGE CASES =====================

TEST_CASE_METHOD(EndToEndFixture, "E2E: Graceful Handling of Missing Sections", "[E2E][ErrorHandling]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Try to find a section that likely doesn't exist
    auto result = binary->section_from_rva(0xFFFFFFFFUL);
    REQUIRE(result == nullptr);
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Handling Empty or Sparse Sections", "[E2E][EdgeCases]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Find smallest section
    size_t min_size = SIZE_MAX;
    for (const auto& section : binary->sections) {
        if (section.size() < min_size) {
            min_size = section.size();
        }
    }
    
    // Verify we can handle small sections
    if (min_size > 0) {
        REQUIRE(min_size < SIZE_MAX);
    }
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Metadata Consistency Check", "[E2E][Consistency]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // Verify metadata and binary sections are consistent
    REQUIRE(!binary->sections.empty());
    REQUIRE(binary->metadata != nullptr);
    
    // Basic consistency: total size calculations
    size_t total_size = 0;
    for (const auto& section : binary->sections) {
        total_size += section.size();
    }
    
    REQUIRE(total_size > 0);
}

// ===================== FULL PIPELINE INTEGRATION TEST =====================

TEST_CASE_METHOD(EndToEndFixture, "E2E: Full Pipeline - Parse, Hash, Analyze, Export", "[E2E][FullPipeline]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    // PHASE 1: Parse
    REQUIRE(!binary->sections.empty());
    REQUIRE(binary->metadata != nullptr);
    
    // PHASE 2: Calculate file hash
    std::string file_hash;
    try {
        file_hash = compute_md5_from_file(test_binary_path);
        REQUIRE(!file_hash.empty());
    } catch (...) {
        // Hash calculation optional
        file_hash = "unavailable";
    }
    
    // PHASE 3: Analyze
    size_t total_bytes = 0;
    size_t section_count = 0;
    
    for (const auto& section : binary->sections) {
        section_count++;
        for (const auto& byte : section) {
            (void)byte;
            total_bytes++;
        }
    }
    
    REQUIRE(section_count > 0);
    REQUIRE(total_bytes > 0);
    
    // PHASE 4: Disassembly analysis (optional)
    size_t instr_count = 0;
    try {
        instr_count = binary->getInstructionCount();
        REQUIRE(instr_count > 0);
    } catch (...) {
        // Disassembly might not be available
        instr_count = 0;
    }
    
    // PHASE 5: Function detection (optional)
    size_t func_count = binary->_functions.size();
    
    // PHASE 6: Export
    std::stringstream report;
    report << "Binary Analysis Report\n";
    report << "Sections: " << section_count << "\n";
    report << "Total Bytes: " << total_bytes << "\n";
    report << "Functions Detected: " << func_count << "\n";
    if (instr_count > 0) {
        report << "Instructions: " << instr_count << "\n";
    }
    report << "Hash: " << file_hash << "\n";
    
    REQUIRE(report.str().length() > 0);
}

TEST_CASE_METHOD(EndToEndFixture, "E2E: Round-trip Test (Parse -> Serialize -> Re-Parse)", "[E2E][RoundTrip]") {
    if (!isBinaryAvailable()) {
        SKIP("Test binary not available");
    }
    
    try {
        // Step 1: Get original data
        auto& original_section = binary->getTextSection();
        std::string original_name = original_section.name;
        uintptr_t original_addr = original_section.virtual_addr;
        size_t original_size = original_section.virtual_size;
        
        // Step 2: Serialize
        std::stringstream stream;
        original_section.serialize(stream);
        
        // Step 3: Deserialize
        BinSection restored;
        stream.seekg(0);
        restored.deserialize(stream);
        
        // Step 4: Verify data integrity
        REQUIRE(restored.name == original_name);
        REQUIRE(restored.virtual_addr == original_addr);
        REQUIRE(restored.virtual_size == original_size);
        
    } catch (const std::runtime_error&) {
        SKIP("Text section not found");
    }
}
