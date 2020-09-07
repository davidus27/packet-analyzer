#include <iostream>
#include <memory>
#include <vector>

#include <pcap.h>
#include "functions.hpp"

void increment_argument(int args[]) { args[0]++; }


int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const uint8_t* packet;
    struct pcap_pkthdr packet_header;
    if(argc > 1)
    {
        pcap_t* handle = pcap_open_offline(argv[1], errbuf);
        if(handle)
        {
            //std::vector<ProcessedPacket> *list = new std::vector<ProcessedPacket>();
            std::unique_ptr<std::vector<ProcessedPacket>> list = std::make_unique<std::vector<ProcessedPacket>>();
            int counter = 0;
            pcap_loop(handle, 0, (pcap_handler)increment_argument, (u_char*)&counter);
            handle = pcap_open_offline(argv[1], errbuf);
            
            list->reserve(counter);
            pcap_loop(handle, 0, (pcap_handler)process_packet, (u_char*)list.get());
            pcap_close(handle);
            std::cout<<"File: " << argv[1] <<" closed\n";

            // ----------------- TEST ---------------------
            int count = 0;
            for(auto a = list->begin(); a != list->end(); a++)
            {
                std::cout << std::dec << "Ramec " << count++ << '\n';
                std::cout << *a << '\n';
            }
            //delete[] list;

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