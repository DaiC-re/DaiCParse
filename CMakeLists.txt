#####################################
# Define Target Information
#####################################
#####################################
# Define Project-Wide Settings
#####################################
cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

# Enables the Visibility Property on all target types
cmake_policy(SET CMP0063 NEW)
# Enables the MSVC_RUNTIME_LIBRARY property on targets
cmake_policy(SET CMP0091 NEW)
# Define the Project Name and Description
project(DaiCParse LANGUAGES CXX DESCRIPTION "DaiCParse is a library for parsing binaries" VERSION 1.0.0)
option(BUILD_TESTING "Build tests" TRUE)
option(BUILD_SHARED_LIBS "Build shared libraries" TRUE)
option(BUILD_WITH_MT "Build libraries as MultiThreaded DLL (Windows Only)" FALSE)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(InstallRequiredSystemLibraries)
include(GenerateExportHeader)


include(./cmake/dependencies.cmake)
include(./cmake/compiler_options.cmake)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(TARGET_NAME DaiCParse)
set(TARGET_INCLUDE_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Enable Qt's MOC for this library
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(TARGET_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/checksums/md5.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/checksums/file_checksum.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/metadata/metadata.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/binary/bin_section.cpp
${CMAKE_CURRENT_SOURCE_DIR}/src/binary/binary.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/binary_view/binary_view.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/hex_utils/hex_utils.cpp)

#####################################
# Support IDE Visualization
#####################################
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${TARGET_SOURCES})

#####################################
# Define Target according to options
#####################################
# if(BUILD_SHARED_LIBS)
  # add_library(${TARGET_NAME} SHARED ${TARGET_SOURCES})
# else()
add_library(${TARGET_NAME} STATIC ${TARGET_SOURCES}
    include/checksums/file_checksum.h include/checksums/md5.h include/checksums/md5_loc.h include/metadata/metadata.hpp
    include/binary/binary.hpp include/binary/bin_section.hpp include/binary_view/binary_view.hpp include/hex_utils/hex_utils.hpp)
# endif()

set_target_properties(${TARGET_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
#####################################
# Define Target Properties and Optional OpenSSL Dependency
#####################################

# generate an export header to expose symbols when using the library
generate_export_header(${TARGET_NAME} EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/exports/${TARGET_NAME}_export.h)


# add target properties such as debug postfix, MSVC Runtime and library version
set_target_properties(${TARGET_NAME} PROPERTIES 
                                      DEBUG_POSTFIX "-d" 
                                      MSVC_RUNTIME_LIBRARY "${MSVC_RUNTIME_TYPE}" 
                                      VERSION ${CMAKE_PROJECT_VERSION}
                                      SOVERSION ${CMAKE_PROJECT_VERSION})

# set target compile options as defined in the cmake/compiler_options.cmake Module
target_compile_options(${TARGET_NAME} PRIVATE ${compiler_options})

# add compiler definition WITH_OPENSSL, if found
target_compile_definitions(${TARGET_NAME} PRIVATE ${compiler_definitions} $<$<BOOL:${OPENSSL_FOUND}>:WITH_OPENSSL>)

# set target link options as defined in the cmake/compiler_options.cmake Module
target_link_options(${TARGET_NAME} PRIVATE ${linker_flags})

# include all the necessary directories
target_include_directories(${TARGET_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/exports>
  PRIVATE 
    ${TARGET_INCLUDE_FOLDER}
    # include OpenSSL directories if present
    $<$<BOOL:${OPENSSL_FOUND}>:${OPENSSL_INCLUDE_DIR}>
    # Any other extra include required
)

# link OpenSSL libraries if present
if(OPENSSL_FOUND)
  target_link_libraries(${TARGET_NAME} PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()
target_link_libraries(${TARGET_NAME} PUBLIC LIEF::LIEF)
target_link_libraries(${TARGET_NAME} PUBLIC capstone)

if(BUILD_TESTING)
	list(APPEND TEST_CASES
	md5_test
	bin_section_test
	binary_test
	end_to_end_test
	)
	foreach(TEST_CASE ${TEST_CASES})
		add_executable(${TEST_CASE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/${TEST_CASE}.cpp)
		target_link_libraries(${TEST_CASE} PRIVATE ${TARGET_NAME} Catch2::Catch2WithMain)
		target_compile_options(${TEST_CASE} PRIVATE ${compiler_options})
		target_compile_definitions(${TEST_CASE} PRIVATE ${compiler_definitions} $<$<BOOL:${OPENSSL_FOUND}>:WITH_OPENSSL>)
		target_link_options(${TEST_CASE} PRIVATE ${linker_flags})

		target_include_directories(${TEST_CASE}
		  PUBLIC
			$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/exports>
		  PRIVATE
			${TARGET_INCLUDE_FOLDER}
			# Any other extra include required
		)

		add_test(NAME ${TEST_CASE} COMMAND ${TEST_CASE})
	endforeach(TEST_CASE ${TEST_CASES})
endif()
