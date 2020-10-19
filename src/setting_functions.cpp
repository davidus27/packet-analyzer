#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include "processed_packet.hpp"


bool ProcesedPacket::is_using(const std::string& protocol) const
{
    // true, if protocol is used in the packet
    return protocol == "TFTP" || protocol == this->application_protocol 
    || this->ether_type.find(protocol) != std::string::npos
    || this->transport_protocol == protocol; 
}

bool ProcesedPacket::found_binding(std::pair<IP, IP> binding) const
{
    // Checks if packet belong to the communication
    if(binding.first == this->ip_dst)
        return binding.second == this->ip_src;
    if(binding.first == this->ip_src)
        return binding.second == this->ip_dst;
    return false;
}


uint16_t ProcesedPacket::get_ether_type()
{
    return big_endian_to_small(*(uint16_t*)(this->data.payload.data() + Ethernet::ETHER_TYPE_II_OFFSET));
}

void ProcesedPacket::set_network_layer(const std::vector<std::pair<int, std::string>>& configuration)
{
    // Getting IP
    for(auto& conf_pair : configuration)
    {
        if(conf_pair.first == get_ether_type())
        {
            this->ether_type = conf_pair.second;
        }
    }
}

void ProcesedPacket::set_transport_layer(const uint8_t* data_start, const std::vector<std::pair<int, std::string>>& configuration)
{
    for(auto& conf_pair : configuration)
    {
        if(conf_pair.first == data_start[9]) // 9 bytes of IP Header
        {
            this->transport_protocol = conf_pair.second;
        }
    }
}
void ProcesedPacket::set_ports(const uint8_t* transport_data_start, const std::vector<std::pair<int, std::string>>& configuration)
{
    for(auto& conf_pair : configuration) // Check TCP config
    {
        if(conf_pair.first == big_endian_to_small(*(uint16_t*)transport_data_start))
        {
            this->src_port = conf_pair.first;
            this->application_protocol = conf_pair.second;
            break;
        }
        if(conf_pair.first == big_endian_to_small(*(uint16_t*)(transport_data_start+2)))
        {
            this->dst_port = conf_pair.first;
            this->application_protocol = conf_pair.second;
            break;
        }
    }
    if(!this->src_port) this->src_port = big_endian_to_small(*(uint16_t*)transport_data_start);
    if(!this->dst_port) this->dst_port = big_endian_to_small(*(uint16_t*)(transport_data_start+2));
}

void ProcesedPacket::set_arp_flags()
{
    if(this->ether_type == "ARP-REQUEST") this->is_starting_packet = true;
    else if(this->ether_type == "ARP-REPLY") this->is_ending_packet = true;
}

void ProcesedPacket::set_flags(const uint8_t* transport_data_start)
{
    if(this->application_protocol == "DNS")
    {
        uint8_t offset = transport_data_start[11];
        auto dns_header = transport_data_start;
        if(this->transport_protocol == "TCP") 
            dns_header += (offset * 4);
        else if(this->transport_protocol == "UDP") dns_header += 8;
        else return;
        dns_header += 2; // ignore ID
        // ignore all bits except last one
        this->is_starting_packet = !((*dns_header) & 0x80);
        this->is_ending_packet = (*dns_header) & 0x80;
    }
    else if(this->transport_protocol == "TCP")
    {
        // FIN or RST
        this->is_ending_packet = transport_data_start[13] & 1 || transport_protocol[13] & 4;
        // SYN without ACK
        this->is_starting_packet = (transport_data_start[13] & 2) && !(transport_data_start[13] & 16);
        return;
    }
    else if(this->application_protocol == "TFTP")
    {
        this->is_starting_packet = transport_data_start[9] & 1;
        this->is_ending_packet = false; 
        return;
    }
}


void ProcesedPacket::set_mac()
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        this->mac_dst[i] = this->data.payload[i];
        this->mac_src[i] = this->data.payload[i + Ethernet::MAC_SIZE];
    }
}

void ProcesedPacket::set_mac_arp(const uint8_t *data_start)
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        this->arp_macs.first[i] = data_start[i+8];
        this->arp_macs.second[i] = data_start[i+18];
    }
}

void ProcesedPacket::set_ip_arp(const uint8_t *data_start)
{        
    // set IP addresses from ARP
    for(int i = 0; i < Ethernet::IP_SIZE; i++)
    {
        this->ip_src[i] = data_start[i+14];
        this->ip_dst[i] = data_start[i+24];
    }
}

void ProcesedPacket::set_ipv4(const uint8_t *data_start)
{
    for(int i = 0; i < Ethernet::IP_SIZE; i++)
    {
        this->ip_src[i] = data_start[i+12];
        this->ip_dst[i] = data_start[i+16];
    }
}