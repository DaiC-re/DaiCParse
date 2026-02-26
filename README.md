# DaiC

DaiC Parse is an library for easely parsing binaries. It leverages the LIEF library but provides more high level and platform independents results. It also integrates the Capstone library for disassembling binaries.

## Available CMake Options

* BUILD_TESTING     - builds the tests (requires `catch2`)
* BUILD_SHARED_LIBS - enables or disables the generation of shared libraries
* BUILD_WITH_MT     - valid only for MSVC, builds libraries as MultiThreaded DLL

## How to build from command line

The project can be built using the following commands:

```shell
cd /path/to/this/project
mkdir -p build # md build (on Windows)
cd build
cmake -DBUILD_TESTING=TRUE -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
cmake --build . --target format
cmake --build . --target package
```

## How to build with Docker (recommended way for dev workflow)

```shell
docker build -t daic-builder .
docker run -it daic-builder
```

## Import DaiCParse in your CMake project

```cmake
Include(FetchContent)

FetchContent_Declare(
  DaiCParse
  GIT_REPOSITORY https://github.com/DaiC-re/DaiCParse.git
)

FetchContent_MakeAvailable(DaiCParse)

add_executable(your_project test.cpp)
target_link_libraries(your_project PRIVATE DaiCParse)
```

## Getting started with DaiCParse

If you want to get started with DaiCParse, please follow the instructions in [GETTING_STARTED.md](docs/GETTING_STARTED.md). It will guide you through the installation process and show you how to use the library.

### License:
Portions of this software are licensed as follows:

- All third party components are licensed under the original license provided by the owner of the applicable component
- All other content not mentioned above is available under the MIT license as defined in [LICENSE](https://github.com/DaiC-re/DaiCParse/blob/master/LICENSE)
  
# Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for more information. This guide is a work in progress, and is updated regularly as the library matures.

