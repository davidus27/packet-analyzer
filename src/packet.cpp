#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <array>


#include <pcap.h>

#include "classes.hpp"


Packet::Packet(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body)
    :captured_size{packet_header->caplen}
{
    this->real_size = (packet_header->len + 4 < 64) ? 64 : packet_header->len + 4;
    this->payload.reserve(packet_header->caplen);
    for(unsigned long i = 0; i < packet_header->caplen; i++)
    {
        this->payload.push_back(packet_body[i]);
    }
}

