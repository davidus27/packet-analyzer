#include <iostream>
#include <iostream>
#include <vector>
#include <array>
#include <fstream>

#include <pcap.h>
#include "classes.hpp"


std::vector<std::pair<IP, int>> get_unique_addresses(const std::vector<ProcessedInfo>& packets)
{
    std::vector<std::pair<IP, int>> used;
    used.push_back({packets[0].ip_src, 1});
    bool in_use = false;
    for(auto& packet : packets)
    {
        for(unsigned long previous = 0; previous < used.size(); previous++)
        {
            if(packet.ip_src == used[previous].first)
            {
                used[previous].second++;
                in_use = true;
                break;
            }
        }
        if(!in_use) used.push_back({packet.ip_src, 1});
        in_use = false;   
    }
    return used;
}

void print_ip_addresses(std::ostream& os, const std::vector<ProcessedInfo>& packets)
{
    os << "IP adresy vysielajucich uzlov:\n";
    std::pair<IP, int> most_frequent;
    for(auto& address : get_unique_addresses(packets))
    {
        os << address.first << '\n';
        if(address.second > most_frequent.second) most_frequent = address;
    }
    os << "Adresa " << most_frequent.first 
    << " ma najväčší počet odoslaných paketov: " 
    << most_frequent.second << ".\n";
}


void print_communications(std::ostream& os, const std::vector<ProcessedInfo>& packets, const std::string& protocol)
{
    std::pair<IP, IP> binding;
    unsigned long communication_num = 1;
    for(unsigned long i = 0; i < packets.size(); i++)
    {
        if(packets[i].is_starting() && packets[i].is_using(protocol)) 
        {
            os << "Komunikacia c." << std::dec << communication_num++ << '\n';
            binding.first = packets[i].ip_dst;
            binding.second = packets[i].ip_src;
            for(unsigned long j = i; j < packets.size(); j++)
            {
                if(packets[j].found_binding(binding) && packets[j].is_using(protocol)) 
                {
                    os << "Ramec " << std::dec << j + 1 << '\n';
                    os << packets[j];
                }
                if(packets[j].is_ending() && packets[j].is_using(protocol)) break;
            }
        }
    }
    
}