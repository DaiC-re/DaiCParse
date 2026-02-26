# Getting Started with DaiCParse

## Prerequisites

Before you start, ensure you have:

- **Compiler**: 
  - Visual Studio 2022 (MSVC)
  - GCC 11+ (Linux)
  - Clang 14+ (macOS)
  
- **Build Tools**:
  - CMake 3.15.0 or later
  - Ninja (recommended) or Visual Studio generator
  
- **Git** (for cloning the repository)

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/DaiC-re/DaiCParse.git
cd DaiCParse
```

### Step 2: Create Build Directory

```bash
mkdir build
cd build
```

### Step 3: Configure with CMake

#### On Windows (MSVC):
```bash
cmake .. -G "Visual Studio 17 2022"
```

#### On Windows (Ninja - Recommended):
```bash
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
```

#### On Linux/macOS:
```bash
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
```

### Step 4: Build

```bash
# With Ninja
ninja

# With Visual Studio
cmake --build . --config Release
```

### Step 5: Run Tests (Optional)

```bash
ctest
```

## Using DaiCParse in Your Project

### Option 1: Use as CMake Subdirectory

```cmake
# In your CMakeLists.txt
add_subdirectory(path/to/DaiCParse)
target_link_libraries(your_target DaiCLib)
```

### Option 2: Use Installed Library

```bash
# Install DaiCParse
cmake --install . --prefix /usr/local
```

```cmake
# In your CMakeLists.txt
find_package(DaiCParse REQUIRED)
target_link_libraries(your_target DaiCParse::DaiCLib)
```

## First Program

### Create a Simple Analysis Tool

```cpp
// main.cpp
#include <binary/binary.hpp>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_file>" << std::endl;
        return 1;
    }

    try {
        // Load the binary
        Binary binary(argv[1]);
        
        // Print basic information
        std::cout << "Binary loaded successfully!" << std::endl;
        std::cout << "Number of sections: " << binary.sections.size() << std::endl;
        
        // List all sections
        std::cout << "\nSections:" << std::endl;
        for (const auto& section : binary.sections) {
            std::cout << "  " << section.name << std::endl;
            std::cout << "    Virtual Address: 0x" << std::hex << section.virtual_addr << std::dec << std::endl;
            std::cout << "    Virtual Size: 0x" << std::hex << section.virtual_size << std::dec << std::endl;
        }
        
        // Try to get text section and count instructions
        try {
            auto& text = binary.getTextSection();
            size_t instr_count = binary.getInstructionCount();
            std::cout << "\nCode Analysis:" << std::endl;
            std::cout << "  Instructions: " << instr_count << std::endl;
            std::cout << "  Functions Detected: " << binary._functions.size() << std::endl;
        } catch (const std::runtime_error& e) {
            std::cout << "\nDisassembly not available: " << e.what() << std::endl;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

### Compile Your Program

```bash
# Using CMake
g++ -std=c++23 -I/path/to/DaiCParse/include main.cpp \
    -L/path/to/DaiCParse/build -lDaiCLib \
    -L/path/to/LIEF/lib -lLIEF \
    -L/path/to/capstone/lib -lcapstone

# Or with CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(MyAnalyzer)

set(CMAKE_CXX_STANDARD 23)

add_subdirectory(path/to/DaiCParse)

add_executable(analyzer main.cpp)
target_link_libraries(analyzer DaiCLib)
```

## Running Your Program

```bash
# Analyze an executable
./analyzer program.exe

# Expected output
# Binary loaded successfully!
# Number of sections: 7
# 
# Sections:
#   .text
#     Virtual Address: 0x1000
#     Virtual Size: 0x5000
#   ...
#
# Code Analysis:
#   Instructions: 1250
#   Functions Detected: 45
```

## Next Steps

Now that you have DaiCParse set up:

1. **Learn the Basics** → Read [USER_GUIDE.md](USER_GUIDE.md)
2. **See Examples** → Check [EXAMPLES.md](EXAMPLES.md)
3. **Understand the API** → Review [API_REFERENCE.md](API_REFERENCE.md)
4. **Explore Features** → Study [ARCHITECTURE.md](ARCHITECTURE.md)

## Troubleshooting

### Build Issues

**Problem**: CMake can't find LIEF or Capstone
```bash
# Solution: Ensure they're installed and in PATH
# Or specify paths manually:
cmake .. -DLIEF_ROOT=/path/to/LIEF -DCAPSTONE_ROOT=/path/to/capstone
```

**Problem**: C++23 not supported
```bash
# Solution: Update your compiler
# MSVC: Use Visual Studio 2022 or later
# GCC: Update to 11.0 or later
# Clang: Update to 14.0 or later
```

### Runtime Issues

**Problem**: "Failed to parse the binary"
```
This usually means the file format is not supported.
DaiCParse supports: PE (Windows), ELF (Linux), Mach-O (macOS)
```

**Problem**: "Text section not found"
```
Not all binaries have a .text section.
Use binary.sections to list available sections.
```

## Configuration Options

### Enable/Disable Tests

```bash
cmake .. -DBUILD_TESTING=ON  # Enable tests (default)
cmake .. -DBUILD_TESTING=OFF # Disable tests
```

### Build Type

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug    # Debug build
cmake .. -DCMAKE_BUILD_TYPE=Release  # Optimized build
```

### Shared/Static Library

```bash
cmake .. -DBUILD_SHARED_LIBS=ON  # Shared library
cmake .. -DBUILD_SHARED_LIBS=OFF # Static library (default)
```

## Common Tasks

### Task 1: Analyze Multiple Binaries

```bash
# In bash/shell
for file in *.exe; do
    ./analyzer "$file" >> analysis.txt
done
```

### Task 2: Process Binary Data

See [EXAMPLES.md](EXAMPLES.md) for detailed examples.

### Task 3: Integrate into Your Project

See [USER_GUIDE.md](USER_GUIDE.md) for integration patterns.

## System-Specific Notes

### Windows
- Use Visual Studio 2022 or Visual Studio Build Tools
- Ninja is recommended for faster builds
- MinGW is not officially supported

### Linux
- GCC 11+ required
- Install dependencies: `apt install cmake ninja-build g++`
- LIEF and Capstone will be automatically downloaded

### macOS
- Xcode Command Line Tools required
- Install with: `xcode-select --install`
- Use Homebrew for dependencies: `brew install cmake ninja`

## Next: Learn the Basics

You're ready to start! Next, read [USER_GUIDE.md](USER_GUIDE.md) to learn:
- How to load binaries
- How to extract sections
- How to analyze code
- How to use security features

---

**Quick Links**:
- [README](README.md) - Overview
- [USER_GUIDE](USER_GUIDE.md) - How to use
- [EXAMPLES](EXAMPLES.md) - Code samples
- [API_REFERENCE](API_REFERENCE.md) - Function reference
- [TROUBLESHOOTING](TROUBLESHOOTING.md) - Common issues
