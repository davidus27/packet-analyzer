include_directories(./src)

include(FindPCAP.cmake)

set(SOURCE_FILES src/main.cpp)
add_executable(analyzer ${SOURCE_FILES})
target_link_libraries(analyzer ${PCAP_LIBRARY})