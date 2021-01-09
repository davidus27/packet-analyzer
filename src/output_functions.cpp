#include <iostream>
#include <iostream>
#include <vector>
#include <array>
#include <fstream>
#include <map>

#include <pcap.h>
#include "processed_packet.hpp"

std::vector<std::pair<IP, int>> get_unique_addresses(const std::vector<ProcesedPacket> &packets)
{
    std::vector<std::pair<IP, int>> used;
    used.push_back({packets[0].ip_src, 1});
    bool in_use = false;
    for (auto &packet : packets)
    {
        for (unsigned long previous = 0; previous < used.size(); previous++)
        {
            if (packet.ip_src == used[previous].first)
            {
                used[previous].second++;
                in_use = true;
                break;
            }
        }
        if (!in_use)
            used.push_back({packet.ip_src, 1});
        in_use = false;
    }
    return used;
}

void print_ip_addresses(std::ostream &os, const std::vector<ProcesedPacket> &packets)
{
    os << "IP addresses of transmitting nodes:\n";
    std::pair<IP, int> most_frequent;
    for (auto &address : get_unique_addresses(packets))
    {
        os << address.first << '\n';
        if (address.second > most_frequent.second)
            most_frequent = address;
    }
    os << "The address " << most_frequent.first
       << " is the most frequent sending address: "
       << most_frequent.second << ".\n";
}

unsigned long size_of_communication(
    const std::vector<ProcesedPacket> &packets,
    std::pair<IP, IP> binding,
    const std::string &protocol,
    unsigned long start)
{
    unsigned long counter{0};
    for (unsigned long j = start; j < packets.size(); j++)
    {
        if (packets[j].found_binding(binding) && packets[j].is_using(protocol))
            counter++;
        if (packets[j].is_ending_packet && packets[j].is_using(protocol))
            break;
    }
    return counter;
}

unsigned long amount_of_packets_using_protocol(
    const std::vector<ProcesedPacket> &packets,
    const std::string &protocol)
{
    unsigned long counter{0};
    for (unsigned long j = 0; j < packets.size(); j++)
    {
        if (packets[j].application_protocol == protocol)
            counter++;
    }
    return counter;
}

void icmp_communications(std::ostream &os, const std::vector<ProcesedPacket> &packets)
{
    std::map<std::pair<IP, IP>, bool> m;
    std::pair<IP, IP> binding;
    unsigned long communication_num = 1;
    for (unsigned long i = 0; i < packets.size(); i++)
    {
        if (packets[i].is_using("ICMP") && !m[binding] && !m[std::pair<IP, IP>{binding.second, binding.first}])
        {
            os << "Communication #" << std::dec << communication_num++ << '\n';
            binding.first = packets[i].ip_dst;
            binding.second = packets[i].ip_src;
            for (unsigned long j = i; j < packets.size(); j++)
            {
                if (packets[j].found_binding(binding) && packets[j].is_using("ICMP") && !m[binding] && !m[std::pair<IP, IP>{binding.second, binding.first}])
                {
                    os << "Frame " << std::dec << j + 1 << '\n';
                    os << packets[j];
                }
            }
            m[binding] = true;
            m[std::pair<IP, IP>{binding.second, binding.first}] = true;
        }
    }
}

void print_communications(std::ostream &os, const std::vector<ProcesedPacket> &packets, const std::string &protocol)
{
    std::pair<IP, IP> binding;
    unsigned long communication_num = 1;
    unsigned long until_now{20}, from_now;
    os << "Amount of packets using protocol " << protocol << ": " << amount_of_packets_using_protocol(packets, protocol) << '\n';
    for (unsigned long i = 0; i < packets.size(); i++)
    {
        if (packets[i].is_starting_packet && packets[i].is_using(protocol))
        {
            os << "Communication #" << std::dec << communication_num++ << '\n';
            binding.first = packets[i].ip_dst;
            binding.second = packets[i].ip_src;

            from_now = size_of_communication(packets, binding, protocol, i);
            from_now = from_now > 40 ? from_now - 20 : 0;

            for (unsigned long j = i; j < packets.size(); j++)
            {
                if (j <= until_now || j > from_now)
                {
                    if (packets[j].found_binding(binding) && packets[j].is_using(protocol))
                    {
                        os << "Frame " << std::dec << j + 1 << '\n';
                        os << packets[j];
                    }
                }
                if (packets[j].is_ending_packet && packets[j].is_using(protocol))
                    break;
            }
        }
    }
}

void execute_asked_function(std::ostream &file, const std::vector<ProcesedPacket> &packets)
{
    std::cout << "Which part of assignment do you what to execute_asked_function?\n";
    std::cout << "1. Print all packets.\n";
    std::cout << "2. Print unique source IP addresses.\n";
    std::cout << "3. Print all communications of specific protocol.\n";
    std::cout << "Input your option[1-3]: ";
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
        if (protocol == "ICMP")
            icmp_communications(file, packets);
        else
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