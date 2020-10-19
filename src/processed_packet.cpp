#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <fstream>
#include <string>
#include <array>
//#include <stdint.h> // non-standard data types (uintX_t)
#include "processed_packet.hpp"

const char* configuration_names[] = {
    "configs/lsap.config",
    "configs/ethertypes.config",
    "configs/ip.config",
    "configs/tcp.config",
    "configs/udp.config"
};

const std::array<std::vector<std::pair<int, std::string>>, CONFIGS_AMOUNT> get_confs()
{
    std::array<std::vector<std::pair<int, std::string>>, CONFIGS_AMOUNT> confs;
    for(int  i = 0; i < CONFIGS_AMOUNT; i++)
    {
        confs[i] = load_configurations(configuration_names[i]);
    }
    return confs;
}
const std::array<std::vector<std::pair<int, std::string>>, CONFIGS_AMOUNT> loaded_configurations = get_confs();


const uint8_t* ProcesedPacket::set_frame_protocols()
{
    // Finds what Ethernet standard is used, set it 
    // and returns start of data for that standard
    
    const uint8_t* packet_body = this->data.payload.data(); // C style pointer to the start of frame 
    // get ethertype/length value
    uint16_t ether_type = big_endian_to_small(*(uint16_t*)(packet_body + Ethernet::ETHER_TYPE_II_OFFSET)); 
    
    // default start for the Ethernet II standard
    const uint8_t* data = packet_body + Ethernet::ETHER_TYPE_II_OFFSET + 2;
    if(ether_type >= 0x600)
    {
        this->ethernet_standard = EthernetStandard::EthernetII;
        return data;
    }
    if(*(uint16_t*)(packet_body + Ethernet::SAP_OFFSET) == 0xffff)
    {
        this->ethernet_standard = EthernetStandard::NovellRAW;
        this->ether_type = "IPX";
        return nullptr;
    }
    this->ethernet_standard = EthernetStandard::IEEE_LLC;
    for(const auto& option : loaded_configurations[0])
    {
        if(option.first == packet_body[Ethernet::SAP_OFFSET])
        {
            this->ether_type = option.second;
        }
    }
    return nullptr;
}


ProcesedPacket::ProcesedPacket(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body)
    :data{packet_header, packet_body}
{
    this->set_mac();
    const uint8_t* data_start = this->set_frame_protocols();    
    if(!data_start) return;
    this->set_network_layer(loaded_configurations[1]);

    if(this->ether_type == "ARP")
    {
        if(data_start[7] == 1) this->ether_type.append("-REQUEST");
        else if(data_start[7] == 2) this->ether_type.append("-REPLY");
        // set IP addresses from ARP
        this->set_mac_arp(data_start);
        this->set_ip_arp(data_start);
        this->set_arp_flags();
    }
    else
    {
        // Getting TCP/UDP/ICMP
        this->set_transport_layer(data_start, loaded_configurations[2]);
        // set IP addresses from IPv4
        this->set_ipv4(data_start);
        // Shift by size of IPv4 header from IHL value.
        // Size is in octets so multiply by 4
        uint8_t ihl_value = data_start[0] & 0xf;
        const uint8_t* transport_data_start = data_start + (ihl_value * 4);

        if(this->transport_protocol == "TCP")
            this->set_ports(transport_data_start, loaded_configurations[3]);
        else if(this->transport_protocol == "UDP")
            this->set_ports(transport_data_start, loaded_configurations[4]);    
        this->set_flags(transport_data_start);
        
    }

}

ProcesedPacket::~ProcesedPacket() {}