#include <iostream>
#include <iomanip> // for number formating
#include <vector>
#include <fstream>
#include <string>

//#include <stdint.h> // non-standard data types (uintX_t)

#include "constants.hpp"
#include "classes.hpp"

std::vector<std::pair<int, std::string>> load_configurations(const std::string& name);

const char* configurations[] = {
    "configs/ethertypes.config",
    "configs/ip.config",
    "configs/lsap.config",
    "configs/tcp.config",
    "configs/udp.config"
};


uint16_t big_endian_to_small(uint16_t value) { return (((value & 0xff)<<8) | ((value & 0xff00)>>8)); }

uint16_t ProcessedInfo::get_ether_type(const uint8_t* packet_body)
{
    switch (this->ethernet_standard)
    {
        case EthernetStandard::EthernetII:
            packet_body += Ethernet::ETHER_TYPE_II_OFFSET;
            break;
        case EthernetStandard::IEEE_LLC_SNAP:
            packet_body += Ethernet::ETHER_TYPE_LLC_OFFSET;
            break;
        default:
            return 0;
    }
    return big_endian_to_small(*(uint16_t*)(packet_body));
}

const uint8_t* ProcessedInfo::set_ethernet_type(const uint8_t* packet_body)
{
    // two byte value stored in the data link layer
    uint16_t ether_type = big_endian_to_small(*(uint16_t*)(packet_body + Ethernet::ETHER_TYPE_II_OFFSET)); 
    
    // default start for the Ethernet II standard
    const uint8_t* data = packet_body + Ethernet::ETHER_TYPE_II_OFFSET + 1; 
    
    if(ether_type >= 0x800)
    {
        this->ethernet_standard = EthernetStandard::EthernetII;
        return data; 
    }
    if(*(uint16_t*)(packet_body + Ethernet::IPX_OFFSET) == 0xffff)
    {
        this->ethernet_standard = EthernetStandard::NovellRAW;
        return nullptr;
        return data + 3; // 3 bytes of IPX header
    }
    if( *(uint16_t*)(packet_body + Ethernet::SAP_OFFSET) == 0xaaaa)
    {
        this->ethernet_standard = EthernetStandard::IEEE_LLC_SNAP;
        return data + 3; // 3 bytes: DSAP + SSAP + Control
    }
    this->ethernet_standard = EthernetStandard::IEEE_LLC;
    return nullptr;
    return data + 8; // 8 bytes: DSAP + SSAP + Control + Vendor + EtherType
}

ProcessedInfo::ProcessedInfo(const struct pcap_pkthdr* packet_header, const uint8_t* packet_body)
    :data{packet_header, packet_body}
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        this->mac_dst[i] = packet_body[i];
        this->mac_src[i] = packet_body[i+Ethernet::MAC_SIZE];
    }
    const uint8_t* data_start = this->set_ethernet_type(packet_body);
    if(data_start)
    {
        for(auto& conf_pair : load_configurations(configurations[0]))
        {
            if(conf_pair.first == this->get_ether_type(packet_body))
            {
                this->ether_type = conf_pair.second;
            }
        }
    }
    
}

ProcessedInfo::~ProcessedInfo() {}

void print_ip_address(std::ostream& os, const uint8_t* address)
{

}

void print_mac_address(std::ostream& os, const uint8_t* address)
{
    for(int i = 0; i < Ethernet::MAC_SIZE; i++)
    {
        os << std::setfill('0') << std::setw(2) << std::hex <<(int) address[i] << ' ';
    }
    os << '\n';
}


std::ostream& operator<<(std::ostream& os, const ProcessedInfo& info)
{
    os << std::dec << "dĺžka rámca poskytnutá pcap API – " 
    << info.data.captured_size << " B\n"
    "dĺžka rámca prenášaného po médiu – "
    << info.data.real_size << " B\n" 
    << "Zdrojová MAC adresa: ";
    print_mac_address(os, info.mac_src);
    os << "Cieľová MAC adresa: ";
    print_mac_address(os, info.mac_dst);
    os << info.ethernet_standard << '\n'
    << info.ether_type << '\n'
    << info.data << '\n';
    /*
    os << "zdrojová IP adresa: ";
    PrintIPAddress(os, info.ip_src);
    os << "cieľová IP adresa: ";
    PrintIPAddress(os, info.ip_dst);
    */
    os << '\n';
    return os;
}

std::ostream& operator<<(std::ostream& os, const std::vector<ProcessedInfo>& list)
{
    int frame_count = 1;
    for(auto a = list.begin(); a != list.end(); a++)
    {
        os << std::dec << "Ramec " << frame_count++ << '\n';
        os << *a;
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const EthernetStandard& standard)
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
    case EthernetStandard::IEEE_LLC_SNAP:
        os << "IEEE 802.3 s LLC a SNAP";
        break;
    default:
        break;
    }
    return os;
}

std::vector<std::pair<int, std::string>> load_configurations(const std::string& name)
{
    std::string text;
    std::ifstream filename{name};
    std::vector<std::pair<int, std::string>> pairs;
    if(filename.is_open())
    {
        int position;
        while(getline(filename, text))
        {
            position = text.find_first_of(' ');
            pairs.push_back({
                std::stoi(text.substr(0, position), nullptr, 16),
                text.substr(position+1, text.size())});
        }
        filename.close();
    }
    else 
    {
        std::cout << "Unable to open file"; 
        return std::vector<std::pair<int, std::string>>();
    }
    return pairs;
}
