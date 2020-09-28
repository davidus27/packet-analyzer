#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <array>


#include <pcap.h>

#include "classes.hpp"

Packet::Packet(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body)
    :real_size{packet_header->len}, captured_size{packet_header->caplen}
{
    this->payload.reserve(packet_header->caplen);
    for(unsigned long i = 0; i < packet_header->caplen; i++)
    {
        this->payload.push_back(packet_body[i]);
    }
}

std::ostream& operator<<(std::ostream& os, const Packet& packet)
{
    for(uint32_t i = 0; i < packet.payload.size(); i++)
    {
        os << std::setfill('0') << std::setw(2) << std::hex << (short) packet.payload[i] << ' ';
        if(!((i+1) % 16)) os << '\n'; 
        else if(!((i+1) % 8)) os << ' '; 
    }
    os << '\n';
    return os;
}