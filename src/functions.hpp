#pragma once
#include "constants.hpp"

enum class EthernetStandard
{
    EthernetII,
    NovellRAW,
    IEEE_LLC,
    IEEE_LLC_SNAP
};


enum class Layer2
{

};

enum class Layer3
{

};

struct ProcessedPacket
{
public:
    ProcessedPacket(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body);
    ~ProcessedPacket();
    friend std::ostream& operator<<(std::ostream& os, const ProcessedPacket& packet);

private:
    const uint32_t packet_size_recv;
    const uint32_t packet_size_real;
    uint8_t mac_dst[Ethernet::MAC_SIZE];
    uint8_t mac_src[Ethernet::MAC_SIZE];
    uint8_t ip_dst[Ethernet::IP_SIZE];
    uint8_t ip_src[Ethernet::IP_SIZE];
    EthernetStandard eth_type;
    Layer2 protocol;
    Layer3 p2;

    const uint8_t* set_ethernet_type(const uint8_t* packet_body);

};


void PrintMACAddress(std::ostream& os, const uint8_t* address);
void PrintIPAddress(std::ostream& os, const uint8_t* address);

void print_packet(
    std::ostream& os, 
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
);

void process_packet(
    std::vector<ProcessedPacket>& args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
);
std::ostream& operator<<(std::ostream& os, const ProcessedPacket& packet);
std::ostream& operator<<(std::ostream& os, const EthernetStandard& standard);