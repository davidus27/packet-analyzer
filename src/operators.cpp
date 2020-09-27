#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <fstream>
#include <string>

//#include <stdint.h> // non-standard data types (uintX_t)
#include "classes.hpp"

void print_ip_address(std::ostream& os, const uint8_t* address)
{
    for(int i = 0; i < Ethernet::IP_SIZE; i++)
    {
        os << std::dec << (int) address[i];
        if(i != Ethernet::IP_SIZE-1) os << '.';
    }
    os << '\n';

}

void print_mac_address(std::ostream& os, const uint8_t* address)
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        os << std::setfill('0') << std::setw(2) << std::hex <<(int) address[i] << ' ';
    }
    os << '\n';
}

std::ostream& operator<<(std::ostream& os, const std::pair<int, std::string>& pair)
{
    if(pair.first)
    {
        os << std::dec << pair.first;
        if (!pair.second.empty())
        {
            os << ' ' << pair.second;;
        }
    }
    os << '\n';
    return os;
}



std::ostream& operator<<(std::ostream& os, const std::vector<ProcessedInfo>& list)
{
    int frame_count = 1;
    for(auto a = list.begin(); a != list.end(); a++)
    {
        os << std::dec << "Ramec " << frame_count++ << '\n';
        os << *a;
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const EthernetStandard& standard)
{
    switch (standard)
    {
    case EthernetStandard::EthernetII:
        os << "Ethernet II ";
        break;
    case EthernetStandard::NovellRAW:
        os << "IEEE 802.3 Raw ";
        break;
    case EthernetStandard::IEEE_LLC:
        os << "IEEE 802.3 s LLC ";
        break;
    case EthernetStandard::IEEE_LLC_SNAP:
        os << "IEEE 802.3 s LLC a SNAP";
        break;
    default:
        break;
    }
    return os;
}


std::ostream& operator<<(std::ostream& os, const ProcessedInfo& info)
{
    os << std::dec << "dĺžka rámca poskytnutá pcap API – " 
    << info.data.captured_size << " B\n"

    "dĺžka rámca prenášaného po médiu – "
    << info.data.real_size << " B\n"

    << info.ethernet_standard << '\n'
    
    << "Zdrojová MAC adresa: ";
    print_mac_address(os, info.mac_src);

    os << "Cieľová MAC adresa: ";
    print_mac_address(os, info.mac_dst);

    os << info.ether_type << '\n'
    << "Zdrojová IP adresa: ";
    print_ip_address(os, info.ip_src);

    os << "Cieľová IP adresa: ";
    print_ip_address(os, info.ip_dst);

    os << info.transport_protocol << '\n'
    << "Zdrojovy port: "
    << info.src_port 
    << "Cielovy port: "
    << info.dst_port
    
    << info.data << '\n';
    return os;
}