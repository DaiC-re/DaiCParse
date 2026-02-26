# API Reference

Complete reference for all public classes, functions, and types in DaiCParse.

## Table of Contents

1. [Core Classes](#core-classes)
2. [Binary Class](#binary-class)
3. [BinSection Class](#binsection-class)
4. [Utility Functions](#utility-functions)
5. [Enums & Types](#enums--types)

---

## Core Classes

### Binary

**Header**: `<binary/binary.hpp>`

Main class for binary analysis.

#### Constructors

```cpp
// Load from file
Binary(const std::string path);

// Default constructor
Binary();
```

#### Public Methods

```cpp
// Section access
std::vector<BinSection> sections;
BinSection& getTextSection();
const BinSection& getTextSection() const;
BinSection* section_from_rva(uint64_t virtual_address);

// Code analysis
size_t getInstructionCount() const;
uintptr_t getTextSectionVirtualAddr() const;

// Function access
std::optional<Function> get_function(std::string& name);
Function* getFunctionAtAdress(uintptr_t addr);
const Function* getFunctionAtAdress(uintptr_t addr) const;

// Metadata
std::unique_ptr<BinaryMetadata> metadata;
BinType type;  // Binary format (PE, ELF, MACHO)
```

#### Public Members (Advanced)

```cpp
std::vector<Function> _functions;           // Detected functions
std::vector<uintptr_t> _disass_checkpoints; // Disassembly checkpoints
size_t _instruction_count;                  // Total instruction count
```

#### Exceptions

- `std::runtime_error` - When text section not found or disassembly fails

---

### BinSection

**Header**: `<binary/bin_section.hpp>`

Represents a section in a binary file.

#### Constructors

```cpp
// With all parameters
BinSection(std::string name, 
          LIEF::span<const uint8_t> content,
          LIEF::span<const uint8_t> padding,
          uintptr_t offset, 
          uintptr_t virtual_addr, 
          size_t virtual_size);

// Simplified constructor
BinSection(std::string name, 
          LIEF::span<const uint8_t> content);

// Default constructor
BinSection();
```

#### Public Members

```cpp
std::string name;                    // Section name (e.g., ".text")
uintptr_t offset;                    // File offset
LIEF::span<const uint8_t> content;   // Section content
LIEF::span<const uint8_t> padding;   // Section padding
uintptr_t virtual_addr;              // Virtual address
size_t virtual_size;                 // Virtual size
```

#### Public Methods

```cpp
// Size
std::size_t size() const;  // Returns content.size() + padding.size()

// Iteration
iterator begin();
iterator end();
const_iterator begin() const;
const_iterator end() const;

// Serialization
void serialize(std::ostream& out) const;
void deserialize(std::istream& in);

// Comparison
bool operator==(const BinSection& other) const;
```

#### Iterators

```cpp
// Range-based for loop
for (const auto& byte : section) {
    // byte is uint8_t
}

// Manual iteration
for (auto it = section.begin(); it != section.end(); ++it) {
    uint8_t byte = *it;
}
```

---

### Binary::Function

**Header**: `<binary/binary.hpp>`

Represents a detected function in the binary.

#### Constructors

```cpp
// Constructor with parameters
Function(const std::string& name, 
        uintptr_t start, 
        uintptr_t end, 
        size_t id);

// Default constructor
Function();
```

#### Public Methods

```cpp
// Access information
std::string getName() const;
uintptr_t getStart() const;
uintptr_t getEnd() const;
uintptr_t getSize() const;      // Returns end - start
uint64_t getId() const;

// Modification
void setName(std::string_view name);

// Serialization
void serialize(std::ostream& out) const;
void deserialize(std::istream& in);

// Comparison
bool operator==(const Function& other) const;
```

---

## Utility Functions

### File Operations

#### compute_md5_from_file

**Header**: `<checksums/file_checksum.h>`

```cpp
const std::string compute_md5_from_file(const std::string_view path);
```

Calculate MD5 hash of a file.

**Parameters**:
- `path` - Path to the file

**Returns**: 
- MD5 hash as hex string (32 characters)

**Exceptions**:
- `std::exception` - If file cannot be read

**Example**:
```cpp
auto hash = compute_md5_from_file("program.exe");
std::cout << "MD5: " << hash << std::endl;  // "d41d8cd98f00b204e9800998ecf8427e"
```

---

#### BinaryFileChecksum::calculateChecksum

**Header**: `<checksums/file_checksum.h>`

```cpp
class BinaryFileChecksum {
public:
    static uint64_t calculateChecksum(const std::string& path);
};
```

Calculate checksum of a binary file.

**Parameters**:
- `path` - Path to the binary file

**Returns**:
- Checksum value as uint64_t

**Example**:
```cpp
auto checksum = BinaryFileChecksum::calculateChecksum("program.exe");
std::cout << "Checksum: " << checksum << std::endl;
```

---

### Hashing

#### md5::md5_t Class

**Header**: `<checksums/md5.h>`

MD5 hash calculator.

```cpp
namespace md5 {
    class md5_t {
    public:
        md5_t();
        void process(const uint8_t* data, size_t length);
        std::string finish();
    };
}
```

**Methods**:
- `process(data, length)` - Add data to hash
- `finish()` - Get final hash digest

**Example**:
```cpp
#include <checksums/md5.h>

md5::md5_t hasher;
std::vector<uint8_t> data = {0x01, 0x02, 0x03};
hasher.process(data.data(), data.size());
std::string digest = hasher.finish();
```

---

## Enums & Types

### BinType

**Header**: `<binary/binary.hpp>`

Binary format enumeration.

```cpp
enum class BinType {
    ELF,        // Linux ELF executable
    PE,         // Windows PE executable
    MACHO,      // macOS Mach-O executable
    UNKNOWN     // Unknown format
};
```

**Usage**:
```cpp
Binary binary("program.exe");
if (binary.type == BinType::PE) {
    std::cout << "Windows executable" << std::endl;
}
```

---

## Common Patterns

### Pattern 1: Safe Section Access

```cpp
try {
    auto& text = binary.getTextSection();
    // Use text section
} catch (const std::runtime_error& e) {
    std::cerr << "Text section not available: " << e.what() << std::endl;
}
```

### Pattern 2: RVA to Section Lookup

```cpp
uintptr_t address = 0x4500;
auto section = binary.section_from_rva(address);

if (section != nullptr) {
    std::cout << "Address in section: " << section->name << std::endl;
} else {
    std::cout << "Address not in any section" << std::endl;
}
```

### Pattern 3: Iterate Sections

```cpp
for (const auto& section : binary.sections) {
    std::cout << "Section: " << section.name << std::endl;
    std::cout << "  Size: " << section.size() << std::endl;
    
    // Iterate content
    for (const auto& byte : section) {
        // Process byte
    }
}
```

### Pattern 4: Find by Predicate

```cpp
// Find specific section
auto it = std::find_if(
    binary.sections.begin(),
    binary.sections.end(),
    [](const BinSection& s) { return s.name == ".data"; }
);

if (it != binary.sections.end()) {
    std::cout << "Found .data section" << std::endl;
}
```

### Pattern 5: Serialize Section

```cpp
#include <fstream>

// Serialize
{
    std::ofstream file("section.bin", std::ios::binary);
    section.serialize(file);
}

// Deserialize
{
    std::ifstream file("section.bin", std::ios::binary);
    BinSection loaded;
    loaded.deserialize(file);
}
```

---

## Type Definitions

### LIEF::span

**From LIEF Library**

Non-owning view of contiguous data.

```cpp
LIEF::span<const uint8_t> content;  // Read-only view of bytes
LIEF::span<const uint8_t> padding;  // Read-only view of padding
```

**Common Operations**:
```cpp
auto size = span.size();           // Size in bytes
auto ptr = span.data();            // Pointer to data
auto byte = span[0];               // Access element
for (auto b : span) { }            // Iterate
```

---

## Headers & Includes

### Main Headers

```cpp
#include <binary/binary.hpp>           // Binary class
#include <binary/bin_section.hpp>      // BinSection class
#include <metadata/metadata.hpp>       // BinaryMetadata
#include <binary_view/binary_view.hpp> // BinaryView
```

### Utility Headers

```cpp
#include <checksums/file_checksum.h>   // File checksums
#include <checksums/md5.h>             // MD5 hashing
#include <hex_utils/hex_utils.hpp>     // Hex utilities
```

---

## Thread Safety

- Binary class: **Not thread-safe** for modifications
- BinSection: **Thread-safe** for reading
- Hashing functions: **Thread-safe**

For multi-threaded use, synchronize access to Binary instances.

---

## Performance Notes

- **Binary loading**: Depends on file size, typically 10-100ms
- **Disassembly**: ~1000 instructions per millisecond
- **Hashing**: ~100MB per second
- **Section iteration**: Memory bandwidth limited

---

## Deprecations

None currently. All APIs are stable.

---

## Further Reading

- [User Guide](USER_GUIDE.md) - Practical usage
- [Examples](EXAMPLES.md) - Code samples
- [Architecture](ARCHITECTURE.md) - Design details
- [LIEF Documentation](https://lief-project.github.io/) - LIEF reference
- [Capstone Documentation](http://www.capstone-engine.org/) - Capstone reference

---

**Quick Links**:
- [README](README.md)
- [User Guide](USER_GUIDE.md)
- [Examples](EXAMPLES.md)
- [Architecture](ARCHITECTURE.md)
