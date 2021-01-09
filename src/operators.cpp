#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <fstream>
#include <string>
#include <array>

//#include <stdint.h> // non-standard data types (uintX_t)
#include "processed_packet.hpp"

std::ostream &operator<<(std::ostream &os, const std::array<uint8_t, Ethernet::IP_SIZE> &address)
{
    for (int i = 0; i < Ethernet::IP_SIZE; i++)
    {
        os << std::dec << (int)address[i];
        if (i != Ethernet::IP_SIZE - 1)
            os << '.';
    }
    //os << '\n';
    return os;
}

bool operator==(std::array<uint8_t, Ethernet::IP_SIZE> &first, std::array<uint8_t, Ethernet::IP_SIZE> &second)
{
    for (long unsigned int i = 0; i < first.size(); i++)
    {
        if (first[i] != second[i])
            return false;
    }
    return true;
}

std::ostream &operator<<(std::ostream &os, const std::array<uint8_t, Ethernet::MAC_SIZE> &address)
{
    for (int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        os << std::setfill('0') << std::setw(2) << std::hex << (int)address[i] << ' ';
    }
    os << '\n';
    return os;
}

std::ostream &operator<<(std::ostream &os, const std::pair<int, std::string> &pair)
{
    if (pair.first)
    {
        os << std::dec << pair.first;
        if (!pair.second.empty())
        {
            os << ' ' << pair.second;
            ;
        }
    }
    os << '\n';
    return os;
}

std::ostream &operator<<(std::ostream &os, const std::vector<ProcesedPacket> &list)
{
    int frame_count = 1;
    for (auto a = list.begin(); a != list.end(); a++)
    {
        os << std::dec << "Frame " << frame_count++ << '\n';
        os << *a;
    }
    return os;
}

std::ostream &operator<<(std::ostream &os, const EthernetStandard &standard)
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
    default:
        break;
    }
    return os;
}

std::ostream &operator<<(std::ostream &os, const Packet &packet)
{
    for (uint32_t i = 0; i < packet.payload.size(); i++)
    {
        os << std::setfill('0') << std::setw(2) << std::hex << (short)packet.payload[i] << ' ';
        if (!((i + 1) % 16))
            os << '\n';
        else if (!((i + 1) % 8))
            os << ' ';
    }
    os << '\n';
    return os;
}

std::ostream &operator<<(std::ostream &os, const ProcesedPacket &info)
{
    os << std::dec << "Frame lenght based on PCAP API - "
       << info.data.captured_size << " B\n"

                                     "Frame length sent through medium - "
       << info.data.real_size << " B\n"

       << info.ethernet_standard << '\n'
       << "Source MAC address: "
       << info.mac_src

       << "Destination MAC address: "
       << info.mac_dst

       << info.ether_type << '\n';
    if (info.ethernet_standard == EthernetStandard::EthernetII)
    {
        os << "Source IP address: "
           << info.ip_src << '\n'

           << "Destination IP address: "
           << info.ip_dst << '\n';
        if (info.ether_type.find("ARP") != std::string::npos)
            os << "Source ARP MAC address: " << info.arp_macs.first
               << "Destination ARP MAC address: " << info.arp_macs.second;

        if (!info.transport_protocol.empty())
            os << info.transport_protocol << '\n';
        if (!info.application_protocol.empty())
            os << info.application_protocol << '\n';

        if (info.src_port)
            os << "Source port: " << (int)info.src_port << '\n';
        if (info.dst_port)
            os << "Destination port: " << (int)info.dst_port << '\n';
    }

    os << info.data << '\n';
    return os;
}