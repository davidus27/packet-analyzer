#include <iostream>
#include <vector>
#include <array>
#include <fstream>
#include <string>

#include <pcap.h>
#include <stdint.h> // non-standard data types (uintX_t)
#include "classes.hpp"


const char* DEFAULT_FILENAME = "program_output.txt";

void process_packet(
    std::vector<ProcessedInfo>& args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
)
{
    if(packet_body)
        args.push_back(ProcessedInfo{packet_header, packet_body});
    else
        std::cout << "No packets found\n";
}


void execute_asked_function(std::ostream& file, const std::vector<ProcessedInfo>& packets)
{
    std::cout << "Which part of assignment do you what to execute_asked_function?\n";
    std::cout << "1. Print all packets.\n";
    std::cout << "2. Print unique source IP addresses.\n";
    std::cout << "3. Print all communications of specific protocol.\n";
    std::cout << "4. Don't know what is fourth one yet >.<\n";
    std::cout << "Input your option[1-4]: ";
    int input;
    std::cin >> input;

    switch (input)
    {
        case 1:
            file << packets << '\n';
            break;
        case 2:
            print_ip_addresses(file, packets);
            break;
        
        case 3:
        {
            std::cout << "What protocol do you want to print? ";
            std::string protocol; // Too lazy to change to lowercases...
            // gets only word, not whole line
            // in the case of problem use geline(cin, protocol) instead
            std::cin >> protocol; 
            print_communications(file, packets, protocol);
            break;
        }

        default:
        {
            std::cout << "Wrong input. Executing default case.\n";
            file << packets << '\n';
            break;
        }
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
            std::vector<ProcessedInfo> packets = std::vector<ProcessedInfo>();

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