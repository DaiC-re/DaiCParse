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

