cmake_minimum_required (VERSION 2.6)

project (parser)

add_compile_options(-std=c++11)
#add_compile_options(-Wall -O2)

#Get Cmake Modules
set ( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/include/cmake/modules/" )

# The version number.
set (parser_VERSION_MAJOR 0)
set (parser_VERSION_MINOR 1)
 
# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/include/parser/parserConfig.hpp.in"
  "${PROJECT_SOURCE_DIR}/include/parser/parserConfig.hpp"
  )

#Find Packages
find_package(PCAP)

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PCAP_INCLUDE_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/include/parser")
 
# Add Libraries
#add_library 	( RawPacketProcessor 	src/processRawPackets.cpp ) 
add_library 	( PcapPacketProcessor 	src/processPcapPacket.cpp )
# add the executable
#add_executable 	( rawParser		src/parserRawSocket.cpp)
add_executable 	( pcapParser 	src/parserPcap.cpp)

#target_link_libraries (rawParser 	RawPacketProcessor)
target_link_libraries (pcapParser 	PcapPacketProcessor pcap)


