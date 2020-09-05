#include <iostream>
#include <pcap.h>
#include "functions.hpp"

// Constants
const char* file_path = "../../vzorky_pcap_na_analyzu/vzorky_pcap_na_analyzu/eth-1.pcap";
constexpr short timeout = 1000; //ms
constexpr short packets_amount = 0; // unlimited


int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(file_path, errbuf);
    const uint8_t* packet;
    struct pcap_pkthdr packet_header;
    int timeout_limit = 10000;
    

    pcap_loop(handle, 0, process_packet, nullptr);

    if(handle)
    {
        pcap_close(handle);
        std::cout<<"File: "<< file_path<<" closed\n";
    }
return 0;
}