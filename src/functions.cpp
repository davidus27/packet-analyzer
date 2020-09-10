#include <iostream>
#include <iomanip> // for number formating
#include <stdint.h> // non-standard data types (uintX_t)
#include <vector>
#include <fstream>
#include <string>

#include <pcap.h>
#include "constants.hpp"
#include "functions.hpp"

uint16_t big_endian_to_small(uint16_t value) { return (((value & 0xff)<<8) | ((value & 0xff00)>>8)); }


Packet::Packet(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body)
    :real_size{packet_header->len}, captured_size{packet_header->caplen}
{
    this->payload.reserve(packet_header->caplen);
    for(unsigned long i = 0; i < packet_header->caplen; i++)
    {
        this->payload.emplace_back(packet_body[i]);
    }
}

const uint8_t* ProcessedInfo::set_ethernet_type(const uint8_t* packet_body)
{
    // two byte value stored in the data link layer
    uint16_t ether_type = big_endian_to_small(*(uint16_t*)(packet_body + Ethernet::ETHER_TYPE_OFFSET)); 
    
    // default start for the Ethernet II standard
    const uint8_t* data = packet_body + Ethernet::ETHER_TYPE_OFFSET + 1; 
    
    if(ether_type >= 0x800)
    {
        this->eth_type = EthernetStandard::EthernetII;
        return data; 
    }
    if(*(uint16_t*)(packet_body + Ethernet::IPX_OFFSET) == 0xffff)
    {
        this->eth_type = EthernetStandard::NovellRAW;
        return data + 3; // 3 bytes of IPX header
    }
    if( *(uint16_t*)(packet_body + Ethernet::SAP_OFFSET) == 0xaaaa)
    {
        this->eth_type = EthernetStandard::IEEE_LLC_SNAP;
        return data + 3; // 3 bytes: DSAP + SSAP + Control
    }
    this->eth_type = EthernetStandard::IEEE_LLC;
    return data + 8; // 8 bytes: DSAP + SSAP + Control + Vendor + EtherType
}

ProcessedInfo::ProcessedInfo(const uint8_t* packet_body, int index)
    :index{index}
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        this->mac_dst[i] = packet_body[i];
        this->mac_src[i] = packet_body[i+Ethernet::MAC_SIZE];
    }
    const uint8_t* data = set_ethernet_type(packet_body);
    // TODO: find protocol etc 

}

ProcessedInfo::~ProcessedInfo()
{
}

void PrintIPAddress(std::ostream& os, const uint8_t* address)
{

}

void PrintMACAddress(std::ostream& os, const uint8_t* address)
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        os << std::setfill('0') << std::setw(2) << std::hex <<(int) address[i] << ' ';
    }
    os << '\n';
}

std::ostream& operator<<(std::ostream& os, const Packet& packet)
{
    for(uint32_t i = 0; i < packet.payload.size(); i++)
    {
        os << std::setfill('0') << std::setw(2) << std::hex << (short) packet.payload[i] << ' ';
        if(!((i+1) % 16)) os << '\n'; 
        else if(!((i+1) % 8)) os << ' '; 
    }
    os << '\n';
    return os;
}


std::ostream& operator<<(std::ostream& os, const ProcessedInfo& info)
{
    os << "Ramec " << std::dec << info.index;

    /*
    os << std::dec << "dĺžka rámca poskytnutá pcap API – " 
    << packet.captured_size << " B \n"
    << "dĺžka rámca prenášaného po médiu – " 
    << packet.real_size <<" B\n" 
    << "Zdrojová MAC adresa: ";
    PrintMACAddress(os, packet.mac_src);
    os << "Cieľová MAC adresa: ";
    PrintMACAddress(os, packet.mac_dst);
    os << packet.eth_type << '\n';
    os << "zdrojová IP adresa: ";
    PrintIPAddress(os, packet.ip_src);
    os << "cieľová IP adresa: ";
    PrintIPAddress(os, packet.ip_dst);
    os << '\n';
    */
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
