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

std::vector<std::pair<int, std::string>> load_configurations(const std::string& name)
{
    std::string text;
    std::ifstream filename{name};
    std::vector<std::pair<int, std::string>> pairs;
    if(filename.is_open())
    {
        int position;
        while(getline(filename, text))
        {
            position = text.find_first_of(' ');
            pairs.push_back({
                std::stoi(text.substr(0, position), nullptr, 16),
                text.substr(position+1, text.size())});
        }
        filename.close();
    }
    else 
    {
        std::cout << "Unable to open file"; 
        return std::vector<std::pair<int, std::string>>();
    }
    return pairs;
}


uint16_t big_endian_to_small(uint16_t value) { return (((value & 0xff)<<8) | ((value & 0xff00)>>8)); }

uint16_t ProcessedInfo::get_ether_type(const uint8_t* packet_body)
{
    switch (this->ethernet_standard)
    {
        case EthernetStandard::EthernetII:
            packet_body += Ethernet::ETHER_TYPE_II_OFFSET;
            break;
        case EthernetStandard::IEEE_LLC_SNAP:
            packet_body += Ethernet::ETHER_TYPE_LLC_OFFSET;
            break;
        default:
            return 0;
    }
    return big_endian_to_small(*(uint16_t*)(packet_body));
}

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
        // Getting IP
        for(auto& conf_pair : load_configurations(configurations[0]))
        {
            if(conf_pair.first == get_ether_type(packet_body))
            {
                this->ether_type = conf_pair.second;
            }
        }
        // Getting TCP/UDP/ICMP
        for(auto& conf_pair : load_configurations(configurations[1]))
        {
            if(conf_pair.first == data_start[9]) // 1 byte of EtherType + 9 bytes of IP Header
            {
                this->transport_protocol = conf_pair.second;
            }
        }
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
            for(auto& conf_pair : load_configurations(configurations[2])) // Check TCP config
            {
                if(conf_pair.first == big_endian_to_small(*(uint16_t*)transport_data_start))
                {
                    this->src_port = conf_pair;
                }
                if(conf_pair.first == big_endian_to_small(*(uint16_t*)(transport_data_start+2)))
                {
                    this->dst_port = conf_pair;
                }
            }
            if(!this->src_port.first) this->src_port.first = big_endian_to_small(*(uint16_t*)transport_data_start);
            if(!this->dst_port.first) this->dst_port.first = big_endian_to_small(*(uint16_t*)(transport_data_start+2));
        }

        else if(this->transport_protocol == "UDP")
        {
            for(auto& conf_pair : load_configurations(configurations[3])) // Check UDP config
            {
               if(conf_pair.first == big_endian_to_small(*(uint16_t*)transport_data_start))
               {
                   this->src_port = conf_pair;
               }
               if(conf_pair.first == big_endian_to_small(*(uint16_t*)(transport_data_start+2)))
               {
                   this->dst_port = conf_pair;
               }
            }
            if(!this->src_port.first) this->src_port.first = big_endian_to_small(*(uint16_t*)transport_data_start);
            if(!this->dst_port.first) this->dst_port.first = big_endian_to_small(*(uint16_t*)transport_data_start+2);
        }
    }
    
}

ProcessedInfo::~ProcessedInfo() {}





