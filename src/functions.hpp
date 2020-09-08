#pragma once
#include "constants.hpp"

enum class EthernetStandard
{
    EthernetII,
    NovellRAW,
    IEE,
    IEE_LLC_SNAP
};

enum class Layer2
{

};

enum class Layer3
{

};

struct ProcessedPacket
{
private:
    const uint32_t packet_size_recv;
    const uint32_t packet_size_real;
    std::vector<uint8_t> tcp_header;
    uint8_t mac_dst[Ethernet::MAC_SIZE];
    uint8_t mac_src[Ethernet::MAC_SIZE];
    uint8_t ip_dst[Ethernet::IP_SIZE];
    uint8_t ip_src[Ethernet::IP_SIZE];

    EthernetStandard eth_type;
    Layer2 protocol;
    Layer3 p2;
    
public:
    ProcessedPacket(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body);
    ~ProcessedPacket();
    friend std::ostream& operator<<(std::ostream& os, const ProcessedPacket& packet);
};


void PrintMACAddress(std::ostream& os, const uint8_t* address);
void PrintIPAddress(std::ostream& os, const uint8_t* address);

void process_packet(
    std::vector<ProcessedPacket>& args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
);
std::ostream& operator<<(std::ostream& os, const ProcessedPacket& packet);