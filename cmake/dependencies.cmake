# Dependencies

# Set up cache directory for dependencies
set(CMAKE_CACHE_DIR "${CMAKE_BINARY_DIR}/.cache")
file(MAKE_DIRECTORY ${CMAKE_CACHE_DIR})

# Required for Testing
if(BUILD_TESTING)
  Include(FetchContent)
  set(FETCHCONTENT_BASE_DIR "${CMAKE_CACHE_DIR}/fetchcontent")

  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.10.0 # or a later release
  )
  FetchContent_MakeAvailable(Catch2)
  FetchContent_Declare(
	googletest
	URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
  )
  # For Windows: Prevent overriding the parent project's compiler/linker settings
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

# NOTE: This submodule does not exist for this example, but it does the same
# thing as FetchContent without the download part
set(vendorLIEF_submodule_dir "${CMAKE_CURRENT_LIST_DIR}/LIEF")
if(EXISTS "${vendorLIEF_submodule_dir}")
  add_subdirectory("${vendorLIEF_submodule_dir}")

# Else, we'll specify how to obtain LIEF another way (downloading)
else()
  # URL of the LIEF repo (Can be your fork)
  set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

  # LIEF's version to be used (can be 'main')
  set(LIEF_VERSION 0.16.6)

  include(FetchContent)

  set(FETCHCONTENT_QUIET FALSE)

  FetchContent_Declare(LIEF
    GIT_REPOSITORY  "${LIEF_GIT_URL}"
    GIT_TAG         ${LIEF_VERSION}
    GIT_SHALLOW 1
  )
  set(LIEF_EXAMPLES OFF CACHE BOOL "Disable building LIEF examples" FORCE)
  FetchContent_MakeAvailable(LIEF)
endif()


FetchContent_Declare(
    capstone
    GIT_REPOSITORY "https://github.com/capstone-engine/capstone.git"
    GIT_TAG "5.0.6"
    GIT_SHALLOW 1
)

set(BUILD_SHARED_LIBS TRUE CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS FALSE CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(capstone)

