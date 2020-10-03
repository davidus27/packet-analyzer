#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <fstream>
#include <string>

#include "classes.hpp"


uint16_t big_endian_to_small(uint16_t value) { return (((value & 0xff)<<8) | ((value & 0xff00)>>8)); }

bool ProcessedInfo::is_starting() const
{
    // returns if packet is starting new communication
    
    return false;
}


bool ProcessedInfo::is_ending() const
{
    // returns if packet is ending existing communication
    return false;
}

bool ProcessedInfo::found_binding(std::pair<IP, IP> binding) const
{
    // Checks if packet belong to the communication
    if(binding.first == this->ip_dst && binding.second == this->ip_src)
        return true;
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

void ProcessedInfo::set_network_layer(const uint8_t* packet_body, const std::vector<std::pair<int, std::string>>& configuration)
{
    // Getting IP
    for(auto& conf_pair : configuration)
    {
        if(conf_pair.first == get_ether_type(packet_body))
        {
            this->ether_type = conf_pair.second;
        }
    }
}

void ProcessedInfo::set_transport_layer(const uint8_t* data_start, const std::vector<std::pair<int, std::string>>& configuration)
{
    for(auto& conf_pair : configuration)
    {
        if(conf_pair.first == data_start[9]) // 9 bytes of IP Header
        {
            this->transport_protocol = conf_pair.second;
        }
    }
}
void ProcessedInfo::set_ports(const uint8_t* transport_data_start, const std::vector<std::pair<int, std::string>>& configuration)
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
