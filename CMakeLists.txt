cmake_minimum_required (VERSION 2.6)
project (parser)


# The version number.
set (parser_VERSION_MAJOR 0)
set (parser_VERSION_MINOR 1)
 
# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/parserConfig.h.in"
  "${PROJECT_BINARY_DIR}/parserConfig.h"
  )
 
# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
 
# Add Libraries


# add the executable
add_executable(parser parser.cpp)
