cmake_minimum_required(VERSION 3.14)
project(fuzz-binary-protocol 
    VERSION 1.0.0
    DESCRIPTION "Binary Protocol Fuzzer"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

option(ENABLE_SANITIZER "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0)
    add_compile_definitions(DEBUG=1)
    if(ENABLE_SANITIZER)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
else()
    add_compile_options(-O2)
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

set(SOURCES
    src/protocol.cpp
    src/mutator.cpp
    src/fuzzer.cpp
)

set(HEADERS
    include/protocol.h
    include/mutator.h
    include/fuzzer.h
)

add_library(fuzzproto STATIC ${SOURCES} ${HEADERS})
target_include_directories(fuzzproto PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_executable(fuzz-binary-protocol src/main.cpp)
target_link_libraries(fuzz-binary-protocol PRIVATE fuzzproto)

enable_testing()

add_executable(test_fuzzer tests/test_fuzzer.cpp)
target_link_libraries(test_fuzzer PRIVATE fuzzproto)

add_test(NAME ProtocolTest COMMAND test_fuzzer protocol)
add_test(NAME MutatorTest COMMAND test_fuzzer mutator)
add_test(NAME FuzzerTest COMMAND test_fuzzer fuzzer)
add_test(NAME IntegrationTest COMMAND test_fuzzer integration)

install(TARGETS fuzz-binary-protocol DESTINATION bin)
install(FILES ${HEADERS} DESTINATION include/fuzzproto)

set(CPACK_PACKAGE_NAME "fuzz-binary-protocol")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Binary Protocol Fuzzer")
include(CPack)
