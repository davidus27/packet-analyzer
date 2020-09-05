#include <iostream>
#include <pcap.h>


void process_packet(
    uint8_t* args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
)
{
    if(!packet_body)
    {
        std::cout << "No packet found\n";
    }
    else {
        std::cout << "Packet's size: " << packet_header->len << '\n';
    }
}