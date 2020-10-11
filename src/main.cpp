#include <iostream>
#include <vector>
#include <array>
#include <fstream>
#include <string>

#include <pcap.h>
#include "processed_packet.hpp"


const char* DEFAULT_FILENAME = "program_output.txt";

void process_packet(
    std::vector<ProcesedPacket>& args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
)
{
    if(packet_body)
        args.push_back(ProcesedPacket{packet_header, packet_body});
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
            std::vector<ProcesedPacket> packets = std::vector<ProcesedPacket>();

            pcap_loop(handle, 0, (pcap_handler)process_packet, (uint8_t*)&packets);
            pcap_close(handle);

            // Declaring ofstream to save program output to file
            std::ofstream file;
            if(argc == 3) file.open(argv[2]);
            else file.open(DEFAULT_FILENAME);
            
            execute_asked_function(file, packets);
            file.close();
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