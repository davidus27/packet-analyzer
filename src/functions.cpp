#include <iostream>
#include <iomanip> // for number formating
#include <pcap.h>
#include <stdint.h>
#include <memory>
#include <vector>

#include "constants.hpp"
#include "functions.hpp"

uint16_t big_endian_to_small(uint16_t value) { return (((value & 0xff)<<8) | ((value & 0xff00)>>8)); }

ProcessedPacket::ProcessedPacket(
    const struct pcap_pkthdr* packet_header, 
    const uint8_t* packet_body
)
    :packet_size_recv{packet_header->len}, packet_size_real{packet_header->caplen}
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        this->mac_dst[i] = *(packet_body+i);
        this->mac_src[i] = *(packet_body+i+Ethernet::MAC_SIZE);
    }
    uint16_t ether_type = big_endian_to_small(*(uint16_t*)(packet_body + Ethernet::ETHER_TYPE_OFFSET)); 
    this->eth_type = ether_type >= 0x0800 ? EthernetStandard::EthernetII : EthernetStandard::NovellRAW;
}

ProcessedPacket::~ProcessedPacket()
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

std::ostream& operator<<(std::ostream& os, const ProcessedPacket& packet)
{
    os << std::dec << "dĺžka rámca poskytnutá pcap API – " 
    << packet.packet_size_recv << " B \n"
    << "dĺžka rámca prenášaného po médiu – " 
    << packet.packet_size_real <<" B\n" 
    << "Zdrojová MAC adresa: ";
    PrintMACAddress(os, packet.mac_src);
    os << "Cieľová MAC adresa: ";
    /*
    PrintMACAddress(os, packet.mac_dst);
    os << "zdrojová IP adresa: ";
    PrintIPAddress(os, packet.ip_src);
    os << "cieľová IP adresa: ";
    PrintIPAddress(os, packet.ip_dst);
    */
    os << '\n';
    return os;
}

void print_packet(
    std::ostream& os, 
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
)
{
    for(uint32_t i = 0; i < packet_header->len; i++)
    {
        os << std::setfill('0') << std::setw(2) << std::hex << (short) packet_body[i] << ' ';
        if(!((i+1) % 16)) os << '\n'; 
        else if(!((i+1) % 8)) os << ' '; 
    }
    os<<'\n';
}


void process_packet(
    std::vector<ProcessedPacket>& args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
)
{
    if(!packet_body)
    {
        std::cout << "No packets found\n";
    }
    else {
        std::cout << "Packet body: \n";
        args.push_back(ProcessedPacket{packet_header, packet_body});
        print_packet(std::cout, packet_header, packet_body);
    }
}