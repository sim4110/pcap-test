#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr* header, const u_char*packet){
    struct libnet_ethernet_hdr*eth_header;
    struct libnet_ipv4_hdr*ip_header;
    struct libnet_tcp_hdr*tcp_header;



	eth_header = (struct libnet_ethernet_hdr*)packet;
	if(ntohs(eth_header->ether_type) == 0x0800 ){
		ip_header = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
		if(ip_header->ip_p == IPPROTO_TCP){

			printf("%u bytes captured\n", header->caplen);

			tcp_header = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_header->ip_hl * 4));

			printf("Ethernet src : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_shost[0],eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5] );
			printf("Ethernet dst : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0],eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5] );

			printf("IP src : %s\n", inet_ntoa(ip_header->ip_src));
			printf("IP dst : %s\n", inet_ntoa(ip_header->ip_dst));

			printf("TCP src port : %u\n", ntohs(tcp_header->th_sport));
			printf("TCP dst port : %u\n", ntohs(tcp_header->th_dport));

			u_char*payload = (u_char*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4));
			int payload_len = ntohs(ip_header->ip_len) - ((ip_header->ip_hl * 4) + (tcp_header->th_off * 4));

			if(payload_len>0){
				printf("payload : ");
				for(int i =0; i<payload_len && i< 20; i++){
					printf("%02x ", payload[i]);
				}
				printf("\n");
			}
			else{
				printf("no payload\n");
			}

		}
		printf("\n");
	}
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        packet_handler(NULL, header, packet);
    }

    pcap_close(pcap);
    return 0;
}
