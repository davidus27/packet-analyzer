#include <iostream>
#include <pcap.h>


std::string file_path = "../../vzorky_pcap_na_analyzu/vzorky_pcap_na_analyzu/";


int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];

    std::string fname = file_path + "eth-1.pcap";
    pcap_t* value = pcap_open_offline(fname.c_str(), errbuf);
    if(value)
    {
        pcap_close(value);
        std::cout<<"File: "<< fname<<" closed\n";
    }

return 0;
}