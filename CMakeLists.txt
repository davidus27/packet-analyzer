include_directories(./src)
cmake_minimum_required(VERSION 3.13)

set(CMAKE_CXX_STANDARD 17)



include(FindPCAP.cmake)

#set(SOURCE_FILES src/main.cpp)
set(SOURCE_FILES
    src/main.cpp
    src/helpful_functions.cpp
    src/operators.cpp
    src/output_functions.cpp
    src/packet.cpp
    src/processed_packet.cpp
    src/setting_functions.cpp
)

add_executable(pcap-analyzer ${SOURCE_FILES})
target_link_libraries(pcap-analyzer ${PCAP_LIBRARY})