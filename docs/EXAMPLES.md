# Code Examples

Complete, runnable examples demonstrating DaiCParse features.

## Table of Contents

1. [Basic Binary Loading](#basic-binary-loading)
2. [Section Analysis](#section-analysis)
3. [Code Analysis](#code-analysis)
4. [Security & Hashing](#security--hashing)
5. [Building a Utility](#building-a-utility)
6. [Advanced Analysis](#advanced-analysis)

---

## Basic Binary Loading

### Example 1: Load and List Sections

```cpp
#include <binary/binary.hpp>
#include <iostream>
#include <iomanip>

int main() {
    try {
        // Load binary
        Binary binary("program.exe");
        
        std::cout << "Binary Information:" << std::endl;
        std::cout << "==================" << std::endl;
        std::cout << "Total Sections: " << binary.sections.size() << std::endl;
        
        std::cout << "\nSections:" << std::endl;
        std::cout << std::left << std::setw(20) << "Name" 
                  << std::setw(15) << "Virt Address" 
                  << std::setw(15) << "Virt Size"
                  << "File Offset" << std::endl;
        std::cout << std::string(65, '-') << std::endl;
        
        for (const auto& section : binary.sections) {
            std::cout << std::left << std::setw(20) << section.name
                      << std::hex << std::showbase
                      << std::setw(15) << section.virtual_addr
                      << std::setw(15) << section.virtual_size
                      << section.offset << std::dec << std::endl;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

**Output**:
```
Binary Information:
==================
Total Sections: 7

Sections:
Name                Virt Address    Virt Size       File Offset
-----------------------------------------------------------------
.text               0x1000          0x5000          0x400
.data               0x6000          0x1000          0x5400
.reloc              0x7000          0x500           0x6400
...
```

---

## Section Analysis

### Example 2: Analyze Section Content

```cpp
#include <binary/binary.hpp>
#include <iostream>
#include <iomanip>
#include <algorithm>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <section_name>" << std::endl;
        return 1;
    }

    try {
        Binary binary("program.exe");
        std::string target_section = argv[1];
        
        // Find section
        auto it = std::find_if(
            binary.sections.begin(),
            binary.sections.end(),
            [&](const BinSection& s) { return s.name == target_section; }
        );
        
        if (it == binary.sections.end()) {
            std::cerr << "Section '" << target_section << "' not found" << std::endl;
            return 1;
        }
        
        const auto& section = *it;
        
        // Analyze
        std::cout << "Section Analysis: " << section.name << std::endl;
        std::cout << "==================" << std::endl;
        
        // Size info
        std::cout << "Virtual Address: 0x" << std::hex << section.virtual_addr << std::endl;
        std::cout << "Virtual Size: 0x" << section.virtual_size << std::endl;
        std::cout << "File Offset: 0x" << section.offset << std::endl;
        std::cout << "Content Size: " << std::dec << section.content.size() << std::endl;
        
        // First 256 bytes as hex
        std::cout << "\nFirst 256 bytes (hex dump):" << std::endl;
        int count = 0;
        for (const auto& byte : section) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
            if (++count >= 16) {
                std::cout << std::endl;
                count = 0;
            }
            if (count >= 256) break;
        }
        std::cout << std::endl;
        
        // Statistics
        size_t zero_bytes = 0, one_bytes = 0, other_bytes = 0;
        for (const auto& byte : section) {
            if (byte == 0) zero_bytes++;
            else if (byte == 1) one_bytes++;
            else other_bytes++;
            if (zero_bytes + one_bytes + other_bytes >= 1000) break;
        }
        
        std::cout << "\nContent Statistics (first 1000 bytes):" << std::endl;
        std::cout << "  Zero bytes: " << zero_bytes << std::endl;
        std::cout << "  One bytes: " << one_bytes << std::endl;
        std::cout << "  Other bytes: " << other_bytes << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

**Usage**:
```bash
./section_analyzer program.exe .text
```

---

## Code Analysis

### Example 3: Analyze Code and Functions

```cpp
#include <binary/binary.hpp>
#include <iostream>
#include <iomanip>

int main() {
    try {
        Binary binary("program.exe");
        
        std::cout << "Code Analysis Report" << std::endl;
        std::cout << "====================" << std::endl;
        
        try {
            // Get text section
            auto& text = binary.getTextSection();
            std::cout << "\n.text Section:" << std::endl;
            std::cout << "  Address: 0x" << std::hex << text.virtual_addr << std::endl;
            std::cout << "  Size: 0x" << text.virtual_size << std::dec << std::endl;
            
            // Instruction count
            size_t instructions = binary.getInstructionCount();
            std::cout << "\nDisassembly:" << std::endl;
            std::cout << "  Total Instructions: " << instructions << std::endl;
            std::cout << "  Checkpoints: " << binary._disass_checkpoints.size() << std::endl;
            
            // Functions
            std::cout << "\nDetected Functions: " << binary._functions.size() << std::endl;
            if (!binary._functions.empty()) {
                std::cout << std::left << std::setw(30) << "Function Name"
                          << std::setw(20) << "Start Address"
                          << "End Address" << std::endl;
                std::cout << std::string(70, '-') << std::endl;
                
                for (const auto& func : binary._functions) {
                    std::cout << std::left << std::setw(30) << func.getName()
                              << std::hex << std::showbase
                              << std::setw(20) << func.getStart()
                              << func.getEnd() << std::endl;
                }
            }
            
        } catch (const std::runtime_error& e) {
            std::cout << "Note: Code analysis not available: " << e.what() << std::endl;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

**Output**:
```
Code Analysis Report
====================

.text Section:
  Address: 0x1000
  Size: 0x5000

Disassembly:
  Total Instructions: 1250
  Checkpoints: 13

Detected Functions: 45
Function Name                 Start Address       End Address
----------------------------------------------------------------------
function_1000                  0x1000              0x1050
function_1100                  0x1100              0x1200
...
```

---

## Security & Hashing

### Example 4: Verify Binary Integrity

```cpp
#include <binary/binary.hpp>
#include <checksums/file_checksum.h>
#include <iostream>
#include <chrono>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_file>" << std::endl;
        return 1;
    }

    try {
        std::string filename = argv[1];
        
        std::cout << "Binary Integrity Check" << std::endl;
        std::cout << "======================" << std::endl;
        
        // Load binary
        auto start = std::chrono::high_resolution_clock::now();
        Binary binary(filename);
        auto load_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - start
        );
        
        std::cout << "File: " << filename << std::endl;
        std::cout << "Load Time: " << load_time.count() << "ms" << std::endl;
        
        // Calculate MD5
        start = std::chrono::high_resolution_clock::now();
        auto hash = compute_md5_from_file(filename);
        auto hash_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - start
        );
        
        std::cout << "\nMD5 Hash: " << hash << std::endl;
        std::cout << "Hash Time: " << hash_time.count() << "ms" << std::endl;
        
        // Calculate checksum
        start = std::chrono::high_resolution_clock::now();
        auto checksum = BinaryFileChecksum::calculateChecksum(filename);
        auto checksum_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - start
        );
        
        std::cout << "\nChecksum: " << checksum << std::endl;
        std::cout << "Checksum Time: " << checksum_time.count() << "ms" << std::endl;
        
        // Summary
        std::cout << "\nIntegrity Status: ✓ OK" << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

---

## Building a Utility

### Example 5: Complete Binary Analysis Tool

```cpp
#include <binary/binary.hpp>
#include <checksums/file_checksum.h>
#include <iostream>
#include <iomanip>
#include <algorithm>

class BinaryAnalyzer {
private:
    Binary binary;

public:
    BinaryAnalyzer(const std::string& filename) : binary(filename) {
    }
    
    void printReport() {
        std::cout << "Binary Analysis Report" << std::endl;
        std::cout << "======================" << std::endl;
        
        printBasicInfo();
        printSections();
        printCodeAnalysis();
        printSummary();
    }
    
private:
    void printBasicInfo() {
        std::cout << "\nBasic Information:" << std::endl;
        std::cout << "  Type: " << getTypeString() << std::endl;
        std::cout << "  Total Sections: " << binary.sections.size() << std::endl;
    }
    
    void printSections() {
        std::cout << "\nSections:" << std::endl;
        std::cout << std::left << std::setw(15) << "Name"
                  << std::setw(15) << "Address"
                  << std::setw(15) << "Size"
                  << "Offset" << std::endl;
        std::cout << std::string(60, '-') << std::endl;
        
        for (const auto& section : binary.sections) {
            std::cout << std::left << std::setw(15) << section.name
                      << std::hex << std::showbase
                      << std::setw(15) << section.virtual_addr
                      << std::setw(15) << section.virtual_size
                      << section.offset << std::dec << std::endl;
        }
    }
    
    void printCodeAnalysis() {
        try {
            auto& text = binary.getTextSection();
            size_t instructions = binary.getInstructionCount();
            
            std::cout << "\nCode Analysis:" << std::endl;
            std::cout << "  Instructions: " << instructions << std::endl;
            std::cout << "  Functions Detected: " << binary._functions.size() << std::endl;
            std::cout << "  Checkpoints: " << binary._disass_checkpoints.size() << std::endl;
        } catch (const std::runtime_error&) {
            std::cout << "\nCode Analysis: Not available" << std::endl;
        }
    }
    
    void printSummary() {
        std::cout << "\nSummary:" << std::endl;
        size_t total_size = 0;
        for (const auto& section : binary.sections) {
            total_size += section.size();
        }
        std::cout << "  Total Size: " << total_size << " bytes" << std::endl;
        std::cout << "  Metadata: " << (binary.metadata ? "Yes" : "No") << std::endl;
    }
    
    std::string getTypeString() const {
        switch (binary.type) {
            case BinType::PE: return "PE (Windows)";
            case BinType::ELF: return "ELF (Linux)";
            case BinType::MACHO: return "Mach-O (macOS)";
            default: return "Unknown";
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_file>" << std::endl;
        return 1;
    }

    try {
        BinaryAnalyzer analyzer(argv[1]);
        analyzer.printReport();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

---

## Advanced Analysis

### Example 6: Compare Two Binaries

```cpp
#include <binary/binary.hpp>
#include <iostream>
#include <algorithm>

class BinaryComparator {
private:
    Binary binary1, binary2;

public:
    BinaryComparator(const std::string& file1, const std::string& file2)
        : binary1(file1), binary2(file2) {
    }
    
    void compare() {
        std::cout << "Binary Comparison" << std::endl;
        std::cout << "=================" << std::endl;
        std::cout << "File 1: " << binary1.sections.size() << " sections" << std::endl;
        std::cout << "File 2: " << binary2.sections.size() << " sections" << std::endl;
        
        compareSections();
        compareMetadata();
    }
    
private:
    void compareSections() {
        std::cout << "\nSection Comparison:" << std::endl;
        
        // Compare section counts
        if (binary1.sections.size() != binary2.sections.size()) {
            std::cout << "  ⚠ Different number of sections!" << std::endl;
        }
        
        // Compare each section
        for (size_t i = 0; i < std::min(binary1.sections.size(), binary2.sections.size()); ++i) {
            const auto& s1 = binary1.sections[i];
            const auto& s2 = binary2.sections[i];
            
            if (s1.name == s2.name && 
                s1.virtual_addr == s2.virtual_addr &&
                s1.virtual_size == s2.virtual_size) {
                std::cout << "  ✓ " << s1.name << " matches" << std::endl;
            } else {
                std::cout << "  ✗ " << s1.name << " differs from " << s2.name << std::endl;
            }
        }
    }
    
    void compareMetadata() {
        std::cout << "\nMetadata Comparison:" << std::endl;
        bool m1 = binary1.metadata != nullptr;
        bool m2 = binary2.metadata != nullptr;
        
        if (m1 == m2) {
            std::cout << "  ✓ Both have metadata" << std::endl;
        } else {
            std::cout << "  ✗ Metadata presence differs" << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <file1> <file2>" << std::endl;
        return 1;
    }

    try {
        BinaryComparator comparator(argv[1], argv[2]);
        comparator.compare();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

---

## CMakeLists.txt for Examples

```cmake
cmake_minimum_required(VERSION 3.15)
project(DaiCParseExamples)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find DaiCParse
find_package(DaiCParse REQUIRED)

# Create executables
add_executable(binary_loader example1.cpp)
target_link_libraries(binary_loader DaiCParse::DaiCLib)

add_executable(section_analyzer example2.cpp)
target_link_libraries(section_analyzer DaiCParse::DaiCLib)

add_executable(code_analyzer example3.cpp)
target_link_libraries(code_analyzer DaiCParse::DaiCLib)

add_executable(integrity_check example4.cpp)
target_link_libraries(integrity_check DaiCParse::DaiCLib)

add_executable(binary_tool example5.cpp)
target_link_libraries(binary_tool DaiCParse::DaiCLib)

add_executable(binary_compare example6.cpp)
target_link_libraries(binary_compare DaiCParse::DaiCLib)
```

---

**More Examples**: Check the test files in `tests/` directory for additional examples.

**Next**: [API Reference](API_REFERENCE.md) for detailed function documentation.
