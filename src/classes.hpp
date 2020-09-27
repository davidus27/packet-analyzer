#pragma once

namespace Ethernet
{
    const uint8_t MAC_SIZE = 6; // bytes
    const uint8_t IP_SIZE = 4; // bytes
    const uint8_t ETHER_TYPE_II_OFFSET = 12; // bytes
    const uint8_t ETHER_TYPE_LLC_OFFSET = 18; // bytes
    const uint8_t IPX_OFFSET = 12; // bytes
    const uint8_t SAP_OFFSET = 12; // bytes
    
}

enum class EthernetStandard
{
    EthernetII,
    NovellRAW,
    IEEE_LLC,
    IEEE_LLC_SNAP
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
    ProcessedInfo(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body);
    ~ProcessedInfo();
    friend std::ostream& operator<<(std::ostream& os, const ProcessedInfo& packet);

protected:
    uint16_t get_ether_type(const uint8_t* packet_body);
    const uint8_t* set_ethernet_type(const uint8_t* packet_body);

private:
    uint8_t mac_dst[Ethernet::MAC_SIZE];
    uint8_t mac_src[Ethernet::MAC_SIZE];
    uint8_t ip_dst[Ethernet::IP_SIZE];
    uint8_t ip_src[Ethernet::IP_SIZE];
    EthernetStandard ethernet_standard;
    std::string ether_type;
    std::string transport_protocol;
    std::string  application_protocol;

    std::pair<uint16_t, std::string> src_port; // value and name of source port
    std::pair<uint16_t, std::string> dst_port; // value and name of destination port 
    
    Packet data;

};


void print_mac_address(std::ostream& os, const uint8_t* address);
void print_ip_address(std::ostream& os, const uint8_t* address);

std::ostream& operator<<(std::ostream& os, const Packet& packet);
std::ostream& operator<<(std::ostream& os, const EthernetStandard& standard);
std::ostream& operator<<(std::ostream& os, const ProcessedInfo& info);
std::ostream& operator<<(std::ostream& os, const std::vector<ProcessedInfo>& list);
