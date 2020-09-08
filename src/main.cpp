#include <iostream>
#include <memory>
#include <vector>

#include <pcap.h>
#include "functions.hpp"

void increment_argument(int args[]) { args[0]++; }


int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if(argc > 1)
    {
        pcap_t* handle = pcap_open_offline(argv[1], errbuf);
        if(handle)
        {
            std::unique_ptr<std::vector<ProcessedPacket>> list = std::make_unique<std::vector<ProcessedPacket>>();
            int counter = 0;
            pcap_loop(handle, 0, (pcap_handler)increment_argument, (uint8_t*)&counter);
            handle = pcap_open_offline(argv[1], errbuf);
            
            list->reserve(counter);
            pcap_loop(handle, 5, (pcap_handler)process_packet, (uint8_t*)list.get());
            pcap_close(handle);
            std::cout<<"File: " << argv[1] <<" closed\n";

            // ----------------- PRINTOUT ---------------------
            int frame_count = 1;
            for(auto a = list->begin(); a != list->end(); a++)
            {
                std::cout << std::dec << "Ramec " << frame_count++ << '\n';
                std::cout << *a << '\n';
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