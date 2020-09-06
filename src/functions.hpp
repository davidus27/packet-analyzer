#pragma once


namespace frame
{
        
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

    class ProcessedPacket
    {
    private:
        const uint32_t packet_size_recv;
        const uint32_t packet_size_real;
        EthernetStandard eth_type;
        const uint8_t* mac_dst;
        const uint8_t* mac_src;
        uint8_t* ip_dst;
        uint8_t* ip_src;
        Layer2 protocol;
        Layer3 p2;
        
    public:
        ProcessedPacket(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body);
        ~ProcessedPacket();
    };
}

void process_packet(
    uint8_t* args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
);