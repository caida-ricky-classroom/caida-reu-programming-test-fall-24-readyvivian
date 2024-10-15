#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;
    int last_octet_count[256] = {0};

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
        unsigned char last_octet = (ip_header->daddr >> 24);
        // The ip_header->daddr is a 32 bits integer.
        // Since the program is running on a little-endian environment, the last octet value is actually stored in the first 8 bits.
        // So by shifting the ip_header->daddr to the right by 24 bits we can get the first 8 bits we need.
        last_octet_count[last_octet]++;

    }

    for (int i = 0; i < 256; i++) {
        printf("Last octet %d: %d\n", i, last_octet_count[i]);
    }

    pcap_close(handle);
    return 0;
}
