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
    //friend std::ostream& operator<<(std::ostream& os, const ProcessedInfo& packet);

    std::array<uint8_t, Ethernet::IP_SIZE> ip_src;
    std::array<uint8_t, Ethernet::MAC_SIZE> mac_dst;
    std::array<uint8_t, Ethernet::MAC_SIZE> mac_src;
    std::array<uint8_t, Ethernet::IP_SIZE> ip_dst;
    EthernetStandard ethernet_standard;

    // should use Short String Optimization, so no allocation
    std::string ether_type;
    std::string transport_protocol;
    std::string application_protocol;

    uint16_t src_port; // value of source port
    uint16_t dst_port; // value of destination port 
    
    Packet data;

private:
    uint16_t get_ether_type(const uint8_t* packet_body);
    const uint8_t* set_ethernet_type(const uint8_t* packet_body);
    void set_network_layer(const uint8_t* packet_body, const std::vector<std::pair<int, std::string>>& configuration);
    void set_transport_layer(const uint8_t* data_start, const std::vector<std::pair<int, std::string>>& configuration);
    void set_ports(const uint8_t* transport_data_start, const std::vector<std::pair<int, std::string>>& configuration);
};


uint16_t big_endian_to_small(uint16_t value);
std::vector<std::pair<int, std::string>> load_configurations(const std::string& name);

// Functions for main execution
// What do user want to execute
void print_ip_addresses(std::ostream& os, const std::vector<ProcessedInfo>& packets);
void print_communications(std::ostream& os, const std::vector<ProcessedInfo>& packets, const std::string& protocol);



std::ostream& operator<<(std::ostream& os, const Packet& packet);
std::ostream& operator<<(std::ostream& os, const EthernetStandard& standard);
std::ostream& operator<<(std::ostream& os, const ProcessedInfo& info);
std::ostream& operator<<(std::ostream& os, const std::vector<ProcessedInfo>& list);
std::ostream& operator<<(std::ostream& os, const std::array<uint8_t, Ethernet::MAC_SIZE>& address);
std::ostream& operator<<(std::ostream& os, const std::array<uint8_t, Ethernet::IP_SIZE>& address);