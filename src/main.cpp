#include <iostream>
#include <memory>
#include <vector>

#include <pcap.h>
#include "functions.hpp"

void increment_argument(int args[]) { args[0]++; }

void packet_printout(std::ostream& os, char* argument, const std::unique_ptr<std::vector<ProcessedPacket>>& list)
{
    int frame_count = 1;
    pcap_t* handle = pcap_open_offline(argument, nullptr);
    struct pcap_pkthdr packet_header;
    for(auto a = list->begin(); a != list->end(); a++)
    {
        os << std::dec << "Ramec " << frame_count++ << '\n';
        os << *a;
        
        const uint8_t* packet = pcap_next(handle, &packet_header);
        //print_packet(os, &packet_header, packet);
        
        os << '\n';
    }
}

int main(int argc, char *argv[])
{
    if(argc > 1)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(argv[1], errbuf);
        if(handle)
        {
            int counter = 0;
            pcap_loop(handle, 0, (pcap_handler)increment_argument, (uint8_t*)&counter);
            handle = pcap_open_offline(argv[1], errbuf);
            
            std::unique_ptr<std::vector<ProcessedPacket>> list = std::make_unique<std::vector<ProcessedPacket>>();
            list->reserve(counter);
            pcap_loop(handle, 0, (pcap_handler)process_packet, (uint8_t*)list.get());
            packet_printout(std::cout, argv[1], list);

            pcap_close(handle);
            std::cout<<"File: " << argv[1] <<" closed\n";            
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