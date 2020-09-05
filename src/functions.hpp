#pragma once

void process_packet(
    uint8_t* args,
    const struct pcap_pkthdr* packet_header,
    const uint8_t* packet_body
);