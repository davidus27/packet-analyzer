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

struct Packet
{
    uint32_t real_size;
    uint32_t captured_size;
    std::vector<uint8_t> payload;
    Packet(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body);
};

struct ProcessedInfo
{
public:
    ProcessedInfo(const uint8_t* packet_body, int index);
    ~ProcessedInfo();
    friend std::ostream& operator<<(std::ostream& os, const ProcessedInfo& packet);

private:
    int index;
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
std::ostream& operator<<(std::ostream& os, const Packet& packet);
std::ostream& operator<<(std::ostream& os, const EthernetStandard& standard);
std::ostream& operator<<(std::ostream& os, const ProcessedInfo& info);