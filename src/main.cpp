#include <iostream>
#include <vector>
#include <array>
#include <fstream>

#include <pcap.h>
#include <stdint.h> // non-standard data types (uintX_t)
#include "classes.hpp"


void process_packet(
    std::vector<ProcessedInfo>& args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
)
{
    if(packet_body)
        args.push_back(ProcessedInfo{packet_header, packet_body});
    else
        std::cout << "No packets found\n";
}

typedef std::pair<std::array<uint8_t, Ethernet::IP_SIZE>, int> ip;

std::vector<ip> get_unique_addresses(std::vector<ProcessedInfo> packets)
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

void print_ip_addresses(std::ostream& os, std::vector<ProcessedInfo> packets)
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

void inc(int& a){a++;}

int main(int argc, char *argv[])
{
    if(argc > 1)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(argv[1], errbuf);
        if(handle)
        {
            std::vector<ProcessedInfo> packets = std::vector<ProcessedInfo>();

            pcap_loop(handle, 0, (pcap_handler)process_packet, (uint8_t*)&packets);
            pcap_close(handle);
            
    
            std::ofstream myfile;
            myfile.open("skuska.txt");
            myfile << packets;

            // Another part of assignment
            print_ip_addresses(myfile, packets);
    
            myfile.close();
        }
        else
        {
            std::cout << "File was not found.\n";
        }
    }
    else
    {
        std::cout << "No argument selected.\n";
    }
return 0;
}