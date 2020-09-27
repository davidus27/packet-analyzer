#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <fstream>
#include <string>

//#include <stdint.h> // non-standard data types (uintX_t)
#include "classes.hpp"

const char* configurations[] = {
    "configs/ethertypes.config",
    "configs/ip.config",
    "configs/tcp.config",
    "configs/udp.config"
};


const uint8_t* ProcessedInfo::set_ethernet_type(const uint8_t* packet_body)
{
    // two byte value stored in the data link layer
    uint16_t ether_type = big_endian_to_small(*(uint16_t*)(packet_body + Ethernet::ETHER_TYPE_II_OFFSET)); 
    
    // default start for the Ethernet II standard
    const uint8_t* data = packet_body + Ethernet::ETHER_TYPE_II_OFFSET + 2; 
    
    if(ether_type >= 0x800)
    {
        this->ethernet_standard = EthernetStandard::EthernetII;
        return data; 
    }
    if(*(uint16_t*)(packet_body + Ethernet::IPX_OFFSET) == 0xffff)
    {
        this->ethernet_standard = EthernetStandard::NovellRAW;
        return nullptr;
        return data + 3; // 3 bytes of IPX header
    }
    if( *(uint16_t*)(packet_body + Ethernet::SAP_OFFSET) == 0xaaaa)
    {
        this->ethernet_standard = EthernetStandard::IEEE_LLC_SNAP;
        return data + 3; // 3 bytes: DSAP + SSAP + Control
    }
    this->ethernet_standard = EthernetStandard::IEEE_LLC;
    return data + 8; // 8 bytes: DSAP + SSAP + Control + Vendor + EtherType
}


ProcessedInfo::ProcessedInfo(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body)
    :data{packet_header, packet_body}
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        this->mac_dst[i] = packet_body[i];
        this->mac_src[i] = packet_body[i+Ethernet::MAC_SIZE];
    }

    const uint8_t* data_start = this->set_ethernet_type(packet_body);
    if(data_start)
    {
        this->set_network_layer(packet_body, configurations[0]);
        // Getting TCP/UDP/ICMP
        this->set_transport_layer(data_start, configurations[1]);

        // Save IP addresses
        for(int i = 0; i < Ethernet::IP_SIZE; i++)
        {
            this->ip_src[i] = data_start[i+12];
            this->ip_dst[i] = data_start[i+16];
        }

        // Shift by size of IPv4 header from IHL value.
        // Size is in octets so multiply by 4
        uint8_t ihl_value = data_start[0] & 0xf;
        const uint8_t* transport_data_start = data_start + (ihl_value * 4);

        if(this->transport_protocol == "TCP")
        {
            this->set_ports(transport_data_start, configurations[2]);
        }
        else if(this->transport_protocol == "UDP")
        {
            this->set_ports(transport_data_start, configurations[3]);    
        }
    }
    
}

ProcessedInfo::~ProcessedInfo() {}





