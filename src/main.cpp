#include <iostream>
#include <memory>
#include <vector>

#include <pcap.h>
#include "functions.hpp"

std::ostream& operator<<(std::ostream& os, const std::vector<ProcessedInfo>& list)
{
    int frame_count = 1;
    for(auto a = list.begin(); a != list.end(); a++)
    {
        os << std::dec << "Ramec " << frame_count++ << '\n';
        os << *a;
        os << '\n';
    }
    return os;
}

void process_packet(
    std::vector<Packet>& args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
)
{
    if(packet_body)
        args.push_back(Packet{packet_header, packet_body});
    else
        std::cout << "No packets found\n";
}


int main(int argc, char *argv[])
{
    if(argc > 1)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(argv[1], errbuf);
        if(handle)
        {
            std::vector<Packet> packets = std::vector<Packet>();
            std::vector<ProcessedInfo> packet_info = std::vector<ProcessedInfo>();

            pcap_loop(handle, 0, (pcap_handler)process_packet, (uint8_t*)&packets);
            pcap_close(handle);
            
            
            packet_info.reserve(packets.size());
            for(unsigned long i = 0; i < packets.size(); i++)
            {
                packet_info.push_back(ProcessedInfo(packets[i].payload.data(), i));
            }
            for(unsigned long i = 0; i < packets.size(); i++)
            {
                std::cout << packet_info[i] << '\n' << packets[i] << '\n';
            }
        }
        else
        {
            std::cout << "File was not found.\n";
        }
    }
    else
    {
        std::cout << "No argument selected.\n";
    }
    

return 0;
}