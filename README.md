# F-Engine Flag Parser
**UDP Packet based F-Engine Flag Parser for CHIME FRB Telescope**

**Version** : _0.0_  
**Status**  : _Initial Development_  

## Build Instructions

**Ubuntu**
```
mkdir build
cmake ../
make
```
**CentOS 7**
```
mkdir build
cmake3 ../
make
```

## Initializing Git Submodules

* Run ```git submodule init``` to initialize local configuration file.
* Run ```git submodule update``` to fetch all submodules.

## External Libraries Used

* [cmake](https://cmake.org/) -- Version >= 2.6
* gtest -- Coming Soon, not implemented yet
* DPDK 2.0 -- Coming Soon, not implemented yet
* [Boost C++ Libraries](http://www.boost.org/)
    * Developed on Boost 1.58.0
    * To install libraries run ```sudo apt-get install libboost-all-dev``` on Ubuntu

## Project Directory Setup

* _bin_     : Output executables go here, both for the app and for any tests and spikes.
* _build_   : Contains all object files, and is removed on a clean.
* _doc_     : Documentation, notes, configuration files etc.
* _include_ : All project header files, necessary third-party header files.
* _lib_     : Any library compiled, or third party libs needed in development.
* _scratch_ : Smaller classes or files to test technologies or ideas. 
* _src_     : The application and only the application’s source files.
* _test_    : All test code files. You do write tests, no?

## Contact

* Shiny Brar --> charanjotbrar@gmail.com