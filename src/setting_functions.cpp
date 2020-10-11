#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <fstream>
#include <string>

#include "processed_packet.hpp"


bool ProcesedPacket::is_using(const std::string& protocol) const
{
    // true, if protocol is used in the packet
    return protocol == this->application_protocol || this->ether_type.find(protocol) != std::string::npos; 
}

bool ProcesedPacket::is_starting() const
{
    // returns if packet is starting new communication
    if(this->transport_protocol == "TCP") 
        return this->syn;
    if(this->ether_type == "ARP-REQUEST") return true;
    return false;
}

bool ProcesedPacket::is_ending() const
{
    // returns if packet is ending existing communication
    if(this->transport_protocol == "TCP") return this->fin_rst;
    if(this->ether_type == "ARP-REPLY") return true;
    return false;
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

void ProcesedPacket::save_mac()
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        this->mac_dst[i] = this->data.payload[i];
        this->mac_src[i] = this->data.payload[i + Ethernet::MAC_SIZE];
    }
}

void ProcesedPacket::save_mac_arp(const uint8_t *data_start)
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        this->mac_src[i] = data_start[i+8];
        this->mac_dst[i] = data_start[i+18];
    }
}

void ProcesedPacket::save_ip_arp(const uint8_t *data_start)
{        
    // Save IP addresses from ARP
    for(int i = 0; i < Ethernet::IP_SIZE; i++)
    {
        this->ip_src[i] = data_start[i+14];
        this->ip_dst[i] = data_start[i+24];
    }
}

void ProcesedPacket::save_ipv4(const uint8_t *data_start)
{
    for(int i = 0; i < Ethernet::IP_SIZE; i++)
    {
        this->ip_src[i] = data_start[i+12];
        this->ip_dst[i] = data_start[i+16];
    }
}