#include <iostream>
#include <iostream>
#include <vector>
#include <array>
#include <fstream>

#include <pcap.h>
#include "classes.hpp"

typedef std::pair<std::array<uint8_t, Ethernet::IP_SIZE>, int> ip;


std::vector<ip> get_unique_addresses(const std::vector<ProcessedInfo>& packets)
{
    std::vector<ip> used;
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
    ip most_frequent;
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

}