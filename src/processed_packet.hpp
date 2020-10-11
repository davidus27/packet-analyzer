#pragma once

constexpr short CONFIGS_AMOUNT = 5;

namespace Ethernet
{
    const uint8_t MAC_SIZE = 6; // bytes
    const uint8_t IP_SIZE = 4; // bytes
    const uint8_t ETHER_TYPE_II_OFFSET = 12; // bytes
    const uint8_t ETHER_TYPE_LLC_OFFSET = 18; // bytes
    const uint8_t SAP_OFFSET = 14; // bytes
    
}

enum class EthernetStandard
{
    EthernetII,
    NovellRAW,
    IEEE_LLC
};

struct Packet
{
    uint32_t real_size;
    uint32_t captured_size;
    std::vector<uint8_t> payload;
    Packet(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body);
};

typedef std::array<uint8_t, Ethernet::IP_SIZE> IP;
typedef std::array<uint8_t, Ethernet::MAC_SIZE> MAC;


struct ProcesedPacket
{
public:
    ProcesedPacket(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body);
    ~ProcesedPacket();
    bool found_binding(std::pair<IP, IP> binding) const;
    bool is_using(const std::string& protocol) const;
    bool is_starting() const;
    bool is_ending() const;
    
    void save_mac();
    void save_mac_arp(const uint8_t *data_start);
    void save_ip_arp(const uint8_t *data_start);
    void save_ipv4(const uint8_t *data_start);
    

    MAC mac_dst;
    MAC mac_src;
    IP ip_dst;
    IP ip_src;
    EthernetStandard ethernet_standard;
    bool syn = false;
    bool fin_rst = false;

    // should use Short String Optimization, so no allocation
    std::string ether_type;
    std::string transport_protocol;
    std::string application_protocol;
    uint16_t src_port = 0; // value of source port
    uint16_t dst_port = 0; // value of destination port 
    
    Packet data;

private:
    uint16_t get_ether_type();
    const uint8_t* set_frame_protocols();
    void set_network_layer(const std::vector<std::pair<int, std::string>>& configuration);
    void set_transport_layer(const uint8_t* data_start, const std::vector<std::pair<int, std::string>>& configuration);
    void set_ports(const uint8_t* transport_data_start, const std::vector<std::pair<int, std::string>>& configuration);
    void set_tcp_flags(const uint8_t* transport_data_start);
};


uint16_t big_endian_to_small(uint16_t value);
std::vector<std::pair<int, std::string>> load_configurations(const std::string& name);
// Functions for main execution
// What do user want to execute
void print_ip_addresses(std::ostream& os, const std::vector<ProcesedPacket>& packets);
void print_communications(std::ostream& os, const std::vector<ProcesedPacket>& packets, const std::string& protocol);


std::ostream& operator<<(std::ostream& os, const Packet& packet);
std::ostream& operator<<(std::ostream& os, const EthernetStandard& standard);
std::ostream& operator<<(std::ostream& os, const ProcesedPacket& info);
std::ostream& operator<<(std::ostream& os, const std::vector<ProcesedPacket>& list);
std::ostream& operator<<(std::ostream& os, const std::array<uint8_t, Ethernet::MAC_SIZE>& address);
std::ostream& operator<<(std::ostream& os, const std::array<uint8_t, Ethernet::IP_SIZE>& address);