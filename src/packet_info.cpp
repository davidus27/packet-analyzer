#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <fstream>
#include <string>
#include <array>


//#include <stdint.h> // non-standard data types (uintX_t)
#include "classes.hpp"

const char* configurations[] = {
    "configs/lsap.config",
    "configs/ethertypes.config",
    "configs/ip.config",
    "configs/tcp.config",
    "configs/udp.config"
};
constexpr short CONFIGS_AMOUNT = 5;

const std::array<std::vector<std::pair<int, std::string>>, CONFIGS_AMOUNT> get_confs()
{
    std::array<std::vector<std::pair<int, std::string>>, CONFIGS_AMOUNT> confs;
    for(int  i = 0; i < CONFIGS_AMOUNT; i++)
    {
        confs[i] = load_configurations(configurations[i]);
    }
    return confs;
}

const std::array<std::vector<std::pair<int, std::string>>, CONFIGS_AMOUNT> loaded_configuration = get_confs();

const uint8_t* ProcessedInfo::set_ethernet_type(const uint8_t* packet_body)
{
    // two byte value stored in the data link layer
    uint16_t ether_type = big_endian_to_small(*(uint16_t*)(packet_body + Ethernet::ETHER_TYPE_II_OFFSET)); 
    
    // default start for the Ethernet II standard
    const uint8_t* data = packet_body + Ethernet::ETHER_TYPE_II_OFFSET + 2; 
    
    if(ether_type >= 0x600)
    {
        this->ethernet_standard = EthernetStandard::EthernetII;
        return data; 
    }
    if(*(uint16_t*)(packet_body + Ethernet::IPX_OFFSET) == 0xffff)
    {
        this->ethernet_standard = EthernetStandard::NovellRAW;
        return nullptr;
    }
    if( *(uint16_t*)(packet_body + Ethernet::SAP_OFFSET) == 0xaaaa)
    {
        this->ethernet_standard = EthernetStandard::IEEE_LLC;
        return nullptr;
    }
    this->ethernet_standard = EthernetStandard::IEEE_LLC_SNAP;
    return data + 8; // 8 bytes: DSAP + SSAP + Control + Vendor + EtherType
}

void ProcessedInfo::save_mac()
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        this->mac_dst[i] = this->data.payload[i];
        this->mac_src[i] = this->data.payload[i+Ethernet::MAC_SIZE];
    }
}

void ProcessedInfo::save_ip_arp(const uint8_t *data_start)
{        
    // Save IP addresses from ARP
    for(int i = 0; i < Ethernet::IP_SIZE; i++)
    {
        this->ip_src[i] = data_start[i+14];
        this->ip_dst[i] = data_start[i+24];
    }
}

void ProcessedInfo::save_ipv4(const uint8_t *data_start)
{
    for(int i = 0; i < Ethernet::IP_SIZE; i++)
    {
        this->ip_src[i] = data_start[i+12];
        this->ip_dst[i] = data_start[i+16];
    }
}

ProcessedInfo::ProcessedInfo(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body)
    :data{packet_header, packet_body}
{
    this->save_mac();
    const uint8_t* data_start = this->set_ethernet_type(packet_body);
    this->set_network_layer(packet_body, loaded_configuration[1]);

    if(this->ether_type == "ARP")
    {
        if(data_start[7] == 1) this->ether_type.append("-REQUEST");
        else if(data_start[7] == 2) this->ether_type.append("-REPLY");
        // Save IP addresses from ARP
        this->save_ip_arp(data_start);
    }
    else
    {
        // Getting TCP/UDP/ICMP
        this->set_transport_layer(data_start, loaded_configuration[2]);
        // Save IP addresses from IPv4
        this->save_ipv4(data_start);
        // Shift by size of IPv4 header from IHL value.
        // Size is in octets so multiply by 4
        uint8_t ihl_value = data_start[0] & 0xf;
        const uint8_t* transport_data_start = data_start + (ihl_value * 4);
        if(this->transport_protocol == "TCP")
        {
            this->set_ports(transport_data_start, loaded_configuration[3]);
            
            if(transport_data_start[13] & 1 || transport_protocol[13] & 4) // FIN or RST
                this->fin_rst = true;
            else if(transport_data_start[13] & 2)
                this->syn = true;
        }
        else if(this->transport_protocol == "UDP")
        {
            this->set_ports(transport_data_start, loaded_configuration[3]);    
        }
    }

}

ProcessedInfo::~ProcessedInfo() {}