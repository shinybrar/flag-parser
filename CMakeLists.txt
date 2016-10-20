cmake_minimum_required (VERSION 2.6)
project (parser)
#Get Cmake Modules
set ( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/lib/cmake/modules/" )

# The version number.
set (parser_VERSION_MAJOR 0)
set (parser_VERSION_MINOR 1)
 
# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/src/parserConfig.h.in"
  "${PROJECT_SOURCE_DIR}/src/parserConfig.h"
  )

#Find Packages
find_package(PCAP)

#Setting up Boost
set(Boost_USE_STATIC_LIBS 	ON)
set(Boost_USE_MULTITHREAD	ON)
set(Boost_USE_STATIC_RUNTIME	OFF)
find_package(Boost 1.58.0 COMPONENTS log )
if(Boost_FOUND)  
  include_directories(${Boost_INCLUDE_DIRS})
  add_executable ( boostLog scratch/boostLog.cpp )
  target_link_libraries (boostLog ${Boost_LIBRARIES} )
endif()
 
# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PCAP_INCLUDE_DIR}")
 
# Add Libraries
add_library ( RawPacketProcessor src/processRawPackets.cpp ) 
add_library ( PcapPacketProcessor src/processPcapPacket.cpp )
add_library ( Logger scratch/boostLog.cpp )
# add the executable
add_executable ( rawParser src/parserRawSocket.cpp)
add_executable ( pcapParser src/parserPcap.cpp)

target_link_libraries (rawParser RawPacketProcessor)
target_link_libraries (pcapParser PcapPacketProcessor pcap)
