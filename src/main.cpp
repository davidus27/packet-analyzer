#include <iostream>
#include <vector>

#include <pcap.h>
#include <stdint.h> // non-standard data types (uintX_t)
#include "classes.hpp"


void process_packet(
    std::vector<ProcessedInfo>& args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
)
{
    if(packet_body)
        args.push_back(ProcessedInfo{packet_header, packet_body});
    else
        std::cout << "No packets found\n";
}


int main(int argc, char *argv[])
{
    if(argc > 1)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(argv[1], errbuf);
        if(handle)
        {
            std::vector<ProcessedInfo> packets = std::vector<ProcessedInfo>();
            pcap_loop(handle, 0, (pcap_handler)process_packet, (uint8_t*)&packets);
            pcap_close(handle);
            std::cout << packets << '\n';
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