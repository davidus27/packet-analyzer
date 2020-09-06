#include <iostream>
#include <iomanip> // for number formating
#include <pcap.h>
#include <stdint.h>
#include <memory>

#include "constants.hpp"
#include "functions.hpp"

uint16_t convert(uint16_t value) { return (((value & 0xff)<<8) | ((value & 0xff00)>>8)); }

namespace frame
{
    ProcessedPacket::ProcessedPacket(
        const struct pcap_pkthdr* packet_header, 
        const uint8_t* packet_body
    )
        :packet_size_recv{packet_header->len}, packet_size_real{packet_header->caplen}
    {

        this->mac_dst = packet_body;
        this->mac_src = packet_body + Ethernet::MAC_SIZE;
        uint16_t* ether_type = (uint16_t*) (packet_body + Ethernet::ETHER_TYPE_OFFSET); 
        std::cout << "Value: " << convert(*ether_type)<< '\n';
        if(convert(*ether_type) >= 2048)
        {
            this->eth_type = frame::EthernetStandard::EthernetII;
        }
        else
        {
            this->eth_type = frame::EthernetStandard::NovellRAW;
        }
    }

    ProcessedPacket::~ProcessedPacket()
    {
    }

}




void process_packet(
    uint8_t* args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
)
{
    if(!packet_body)
    {
        std::cout << "No packets found\n";
    }
    else {
        std::cout << "Packet body: \n";

        frame::ProcessedPacket my_packet(packet_header, packet_body);
        for(int i = 0; i < packet_header->len; i++)
        {
            
            std::cout << std::setfill('0') << std::setw(2) << std::hex << (short) packet_body[i] << ' ';
            if(!((i+1) % 10)) std::cout << '\n'; 
        }
        std::cout << '\n';
    }
}