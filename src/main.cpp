#include <iostream>
#include <pcap.h>
#include "functions.hpp"

int main(int argc, char *argv[])
{

    char errbuf[PCAP_ERRBUF_SIZE];
    const uint8_t* packet;
    struct pcap_pkthdr packet_header;
    if(argc > 1)
    {
        pcap_t* handle = pcap_open_offline(argv[1], errbuf);
        if(handle)
        {
            pcap_loop(handle, 0, process_packet, nullptr);
            pcap_close(handle);
            std::cout<<"File: "<< argv[1]<<" closed\n";
        }
        else
        {
            std::cout << "File was not found.\n";
        }
    }
    else
    {
        std::cout << "No argument selected.\n";
    }
    
return 0;
}