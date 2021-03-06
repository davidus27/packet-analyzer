#pragma once

constexpr short CONFIGS_AMOUNT = 5;

namespace Ethernet
{
    const uint8_t MAC_SIZE = 6; // bytes
    const uint8_t IP_SIZE = 4; // bytes
    const uint8_t ETHER_TYPE_II_OFFSET = 12; // bytes
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
    IP ip_dst;
    IP ip_src;
    bool is_starting_packet = false;
    bool is_ending_packet = false;
    std::string application_protocol;
private:
    MAC mac_dst;
    MAC mac_src;
    std::pair<MAC, MAC> arp_macs;
    EthernetStandard ethernet_standard;

    // should use Short String Optimization, so no allocation
    std::string ether_type;
    std::string transport_protocol;
    uint16_t src_port = 0; // value of source port
    uint16_t dst_port = 0; // value of destination port     
    Packet data;

    uint16_t get_ether_type();
    const uint8_t* set_frame_protocols();
    void set_network_layer(const std::vector<std::pair<int, std::string>>& configuration);
    void set_transport_layer(const uint8_t* data_start, const std::vector<std::pair<int, std::string>>& configuration);
    void set_ports(const uint8_t* transport_data_start, const std::vector<std::pair<int, std::string>>& configuration);
    void set_arp_flags();
    void set_flags(const uint8_t* transport_data_start);
    void set_mac();
    void set_mac_arp(const uint8_t *data_start);
    void set_ip_arp(const uint8_t *data_start);
    void set_ipv4(const uint8_t *data_start);
    friend std::ostream& operator<<(std::ostream& os, const ProcesedPacket& info);

};


uint16_t big_endian_to_small(uint16_t value);
std::vector<std::pair<int, std::string>> load_configurations(const std::string& name);
// Functions for main execution
// What do user want to execute
void execute_asked_function(std::ostream& file, const std::vector<ProcesedPacket>& packets);

std::ostream& operator<<(std::ostream& os, const Packet& packet);
std::ostream& operator<<(std::ostream& os, const EthernetStandard& standard);
std::ostream& operator<<(std::ostream& os, const ProcesedPacket& info);
std::ostream& operator<<(std::ostream& os, const std::vector<ProcesedPacket>& list);
std::ostream& operator<<(std::ostream& os, const MAC& address);
std::ostream& operator<<(std::ostream& os, const IP& address);