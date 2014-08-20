cmake_minimum_required (VERSION 2.6)
project (emulateHost)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${emulateHost_SOURCE_DIR}/cmake)
find_package(PCAP REQUIRED)
add_definitions(-std=c++11)

INCLUDE(CompilerFlags)

# Compiler setup
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${VALID_FLAGS}")

# testing
FIND_PACKAGE(CPPUNIT)
if (CPPUNIT_FOUND)
  enable_testing()
  add_subdirectory(tests)
endif (CPPUNIT_FOUND)

add_subdirectory(src)
