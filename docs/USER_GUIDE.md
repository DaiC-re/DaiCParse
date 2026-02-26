# User Guide - How to Use DaiCParse

## Table of Contents

1. [Loading Binaries](#loading-binaries)
2. [Working with Sections](#working-with-sections)
3. [Code Analysis](#code-analysis)
4. [Metadata](#metadata)
5. [Security Operations](#security-operations)
6. [Data Serialization](#data-serialization)
7. [Error Handling](#error-handling)
8. [Best Practices](#best-practices)

---

## Loading Binaries

### Basic Loading

The simplest way to load a binary:

```cpp
#include <binary/binary.hpp>

Binary binary("path/to/binary.exe");
// Binary is now loaded and ready to use
```

### Checking Binary Type

```cpp
Binary binary("program.exe");

if (binary.type == BinType::PE) {
    std::cout << "Windows PE executable" << std::endl;
} else if (binary.type == BinType::ELF) {
    std::cout << "Linux ELF executable" << std::endl;
} else if (binary.type == BinType::MACHO) {
    std::cout << "macOS Mach-O executable" << std::endl;
}
```

### Error Handling

```cpp
try {
    Binary binary("program.exe");
    // Use binary
} catch (const std::exception& e) {
    std::cerr << "Failed to load binary: " << e.what() << std::endl;
}
```

---

## Working with Sections

### List All Sections

```cpp
Binary binary("program.exe");

std::cout << "Sections in binary:" << std::endl;
for (const auto& section : binary.sections) {
    std::cout << "Name: " << section.name << std::endl;
    std::cout << "  Virtual Address: 0x" << std::hex << section.virtual_addr << std::endl;
    std::cout << "  Virtual Size: 0x" << section.virtual_size << std::endl;
    std::cout << "  File Offset: 0x" << section.offset << std::endl;
    std::cout << "  Content Size: " << std::dec << section.content.size() << std::endl;
}
```

### Get Specific Section

```cpp
// Get .text section (code section)
try {
    auto& text_section = binary.getTextSection();
    std::cout << "Text section found: " << text_section.name << std::endl;
    std::cout << "Size: " << text_section.virtual_size << std::endl;
} catch (const std::runtime_error& e) {
    std::cerr << "Text section not found" << std::endl;
}
```

### Find Section by Name

```cpp
auto it = std::find_if(
    binary.sections.begin(),
    binary.sections.end(),
    [](const BinSection& s) { return s.name == ".data"; }
);

if (it != binary.sections.end()) {
    std::cout << "Found .data section at 0x" << std::hex << it->virtual_addr << std::endl;
}
```

### Iterate Through Section Data

```cpp
auto& section = binary.getTextSection();

std::cout << "First 16 bytes of " << section.name << ":" << std::endl;
int count = 0;
for (const auto& byte : section) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    if (++count >= 16) break;
}
```

### Check Section Properties

```cpp
auto& section = binary.getTextSection();

if (section.virtual_size > 0) {
    std::cout << "Section contains data" << std::endl;
}

if (section.size() > 1000000) {
    std::cout << "Section is large (> 1MB)" << std::endl;
}

// Get address range
auto start = section.virtual_addr;
auto end = section.virtual_addr + section.virtual_size;
std::cout << "Address range: 0x" << std::hex << start << " - 0x" << end << std::endl;
```

---

## Code Analysis

### Count Instructions

```cpp
try {
    Binary binary("program.exe");
    size_t count = binary.getInstructionCount();
    std::cout << "Total x86_64 instructions: " << count << std::endl;
} catch (const std::runtime_error& e) {
    std::cerr << "Could not disassemble code: " << e.what() << std::endl;
}
```

### Get Text Section Address

```cpp
try {
    uintptr_t text_addr = binary.getTextSectionVirtualAddr();
    std::cout << "Text section starts at: 0x" << std::hex << text_addr << std::endl;
} catch (const std::runtime_error& e) {
    std::cerr << "Text section not available" << std::endl;
}
```

### Find Functions

```cpp
Binary binary("program.exe");

std::cout << "Detected " << binary._functions.size() << " functions:" << std::endl;
for (const auto& func : binary._functions) {
    std::cout << "  " << func.getName() << std::endl;
    std::cout << "    Start: 0x" << std::hex << func.getStart() << std::endl;
    std::cout << "    End: 0x" << func.getEnd() << std::endl;
    std::cout << "    Size: 0x" << (func.getEnd() - func.getStart()) << std::endl;
}
```

### Find Function at Address

```cpp
uintptr_t address = 0x4000;
auto func = binary.getFunctionAtAdress(address);

if (func != nullptr) {
    std::cout << "Found function: " << func->getName() << std::endl;
} else {
    std::cout << "No function at address 0x" << std::hex << address << std::endl;
}
```

---

## Metadata

### Access Metadata

```cpp
Binary binary("program.exe");

if (binary.metadata != nullptr) {
    std::cout << "Metadata available" << std::endl;
    // Use binary.metadata for detailed info
} else {
    std::cout << "No metadata" << std::endl;
}
```

### Get Binary Properties

```cpp
Binary binary("program.exe");

// Example metadata access (details depend on binary metadata implementation)
if (binary.metadata) {
    // std::cout << "Architecture: " << binary.metadata->getArchitecture() << std::endl;
    // std::cout << "Entry Point: 0x" << std::hex << binary.metadata->getEntryPoint() << std::endl;
}
```

---

## Security Operations

### Calculate MD5 Hash

```cpp
#include <checksums/file_checksum.h>

std::string hash = compute_md5_from_file("program.exe");
std::cout << "MD5: " << hash << std::endl;
```

### Verify File Integrity

```cpp
#include <checksums/file_checksum.h>

// Calculate checksum
auto checksum = BinaryFileChecksum::calculateChecksum("program.exe");
std::cout << "Checksum: " << checksum << std::endl;

// Compare with expected checksum
if (checksum == expected_checksum) {
    std::cout << "File integrity verified" << std::endl;
} else {
    std::cout << "WARNING: File may have been modified" << std::endl;
}
```

### Hash Binary Content

```cpp
#include <checksums/md5.h>

Binary binary("program.exe");

// Calculate hash of binary sections
md5::md5_t hasher;
for (const auto& section : binary.sections) {
    for (const auto& byte : section) {
        uint8_t b = byte;
        hasher.process(&b, 1);
    }
}

// Get hash digest
std::string digest = hasher.finish();
std::cout << "Binary hash: " << digest << std::endl;
```

---

## Data Serialization

### Serialize a Section

```cpp
#include <binary/bin_section.hpp>
#include <fstream>

Binary binary("program.exe");
auto& section = binary.getTextSection();

// Serialize to file
std::ofstream file("section.bin", std::ios::binary);
section.serialize(file);
file.close();

std::cout << "Section serialized to section.bin" << std::endl;
```

### Deserialize a Section

```cpp
#include <binary/bin_section.hpp>
#include <fstream>

std::ifstream file("section.bin", std::ios::binary);
BinSection loaded_section;
loaded_section.deserialize(file);
file.close();

std::cout << "Section loaded: " << loaded_section.name << std::endl;
std::cout << "Size: " << loaded_section.size() << std::endl;
```

### Round-Trip Verification

```cpp
// Original
auto& original = binary.getTextSection();

// Serialize
std::stringstream stream;
original.serialize(stream);

// Deserialize
BinSection restored;
stream.seekg(0);
restored.deserialize(stream);

// Verify
if (original.name == restored.name &&
    original.virtual_addr == restored.virtual_addr &&
    original.virtual_size == restored.virtual_size) {
    std::cout << "Round-trip successful!" << std::endl;
}
```

---

## Address Mapping

### Find Section by Address

```cpp
Binary binary("program.exe");

uintptr_t address = 0x4500;
auto section = binary.section_from_rva(address);

if (section != nullptr) {
    std::cout << "Address 0x" << std::hex << address << " is in section: " << section->name << std::endl;
} else {
    std::cout << "Address not found in any section" << std::endl;
}
```

### Check Address Range

```cpp
auto& text = binary.getTextSection();

uintptr_t addr = 0x4500;
bool in_range = (addr >= text.virtual_addr) && 
                (addr < text.virtual_addr + text.virtual_size);

if (in_range) {
    std::cout << "Address is in .text section" << std::endl;
}
```

---

## Error Handling

### Handle Missing Sections

```cpp
try {
    auto& text = binary.getTextSection();
    // Use text section
} catch (const std::runtime_error& e) {
    std::cerr << "Text section not available: " << e.what() << std::endl;
    // Handle gracefully
}
```

### Handle Parsing Failures

```cpp
try {
    Binary binary("unknown.bin");
} catch (const std::exception& e) {
    std::cerr << "Error loading binary: " << e.what() << std::endl;
    // Could be:
    // - Unsupported format
    // - Corrupted file
    // - File not found
}
```

### Validate Data

```cpp
Binary binary("program.exe");

// Check if sections are valid
if (binary.sections.empty()) {
    std::cerr << "Binary has no sections!" << std::endl;
    return false;
}

// Check metadata
if (!binary.metadata) {
    std::cerr << "No metadata available" << std::endl;
}

return true;
```

---

## Best Practices

### 1. Always Check for Availability

```cpp
// ❌ BAD: May throw exception
auto& text = binary.getTextSection();

// ✅ GOOD: Check first
try {
    auto& text = binary.getTextSection();
    // Use text
} catch (const std::runtime_error&) {
    // Handle error
}
```

### 2. Use const Where Possible

```cpp
// ✅ GOOD: Mark as const to prevent accidental modification
void analyzeSection(const BinSection& section) {
    std::cout << section.name << std::endl;
    for (const auto& byte : section) {
        // Process byte
    }
}
```

### 3. Use Smart Pointers

```cpp
// ✅ GOOD: Use unique_ptr for automatic cleanup
std::unique_ptr<Binary> binary = std::make_unique<Binary>("program.exe");
```

### 4. Check Return Values

```cpp
// ✅ GOOD: Always check pointers before using
auto func = binary.getFunctionAtAdress(0x4000);
if (func != nullptr) {
    std::cout << func->getName() << std::endl;
}
```

### 5. Use Ranges When Applicable

```cpp
// ✅ GOOD: Use range-based for
for (const auto& section : binary.sections) {
    // Process section
}

// ✅ GOOD: Iterate through content
for (const auto& byte : section) {
    // Process byte
}
```

### 6. Cache Results

```cpp
// ✅ GOOD: Cache frequently used values
size_t instr_count = binary.getInstructionCount();
for (int i = 0; i < 100; ++i) {
    // Use instr_count, not binary.getInstructionCount()
}
```

### 7. Use Meaningful Names

```cpp
// ✅ GOOD: Clear variable names
auto& code_section = binary.getTextSection();
auto total_instructions = binary.getInstructionCount();

// ❌ BAD: Unclear names
auto& s = binary.getTextSection();
auto n = binary.getInstructionCount();
```

---

## Common Patterns

### Pattern 1: Analyze All Sections

```cpp
Binary binary("program.exe");

for (const auto& section : binary.sections) {
    std::cout << "Section: " << section.name << std::endl;
    
    size_t bytes = 0;
    for (const auto& b : section) {
        (void)b;
        bytes++;
    }
    
    std::cout << "  Bytes: " << bytes << std::endl;
}
```

### Pattern 2: Find and Analyze Code

```cpp
Binary binary("program.exe");

try {
    auto& text = binary.getTextSection();
    size_t instructions = binary.getInstructionCount();
    
    std::cout << "Code Analysis:" << std::endl;
    std::cout << "  Section Size: " << text.virtual_size << std::endl;
    std::cout << "  Instructions: " << instructions << std::endl;
    std::cout << "  Functions: " << binary._functions.size() << std::endl;
} catch (const std::runtime_error&) {
    std::cout << "No code to analyze" << std::endl;
}
```

### Pattern 3: Verify Integrity

```cpp
Binary binary("program.exe");

auto hash = compute_md5_from_file("program.exe");
std::cout << "Binary Hash: " << hash << std::endl;

// Perform analysis
for (const auto& section : binary.sections) {
    // ... analysis ...
}

// Verify binary is unchanged
auto hash_after = compute_md5_from_file("program.exe");
if (hash == hash_after) {
    std::cout << "Binary integrity verified" << std::endl;
}
```

---

## Next Steps

- **See Working Examples**: [EXAMPLES.md](EXAMPLES.md)
- **API Details**: [API_REFERENCE.md](API_REFERENCE.md)
- **How It Works**: [ARCHITECTURE.md](ARCHITECTURE.md)

---

**Quick Links**:
- [README](README.md)
- [Getting Started](GETTING_STARTED.md)
- [EXAMPLES](EXAMPLES.md)
- [API Reference](API_REFERENCE.md)
