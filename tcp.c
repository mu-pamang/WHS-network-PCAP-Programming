#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h> // 추가
#include "myheader.h" // Custom header file

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
} // 사용법 출력

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    } // 인자가 잘못된 경우

    char *interface = argv[1]; // 인터페이스를 인자로 받음
    char errbuf[PCAP_ERRBUF_SIZE]; // 에러 버퍼

    pcap_t *pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    } // 에러 처리

    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        struct ethheader *ethernet;
        struct ipheader *ipv4;
        struct tcpheader *tcp;

        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        } // 에러 처리

        ethernet = (struct ethheader *)packet;
        ipv4 = (struct ipheader *)(packet + sizeof(struct ethheader));
        tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ipv4->iph_ihl * 4));

        // Ethernet 헤더 정보 출력
        printf("\n====== Ethernet Header ======\n");
        printf("Source MAC address : %02X:%02X:%02X:%02X:%02X:%02X\n", ethernet->ether_shost[0],
               ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3],
               ethernet->ether_shost[4], ethernet->ether_shost[5]);
        printf("Destination MAC address : %02X:%02X:%02X:%02X:%02X:%02X\n", ethernet->ether_dhost[0],
               ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3],
               ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

        // IPv4 헤더 정보 출력
        printf("\n====== IP Header ======\n");
        printf("Source IP address : %s\n", inet_ntoa(ipv4->iph_sourceip));
        printf("Destination IP address : %s\n", inet_ntoa(ipv4->iph_destip));

        // TCP 헤더 정보 출력
        printf("\n====== TCP Header ======\n");
        printf("Source PORT : %d\n", ntohs(tcp->tcp_sport));
        printf("Destination PORT : %d\n", ntohs(tcp->tcp_dport));

        // 메시지 출력
        printf("Message : ");
        int payload_length = ntohs(ipv4->iph_len) - (ipv4->iph_ihl * 4) - (TH_OFF(tcp) * 4);
        for (int i = 0; i < payload_length && i < 16; i++) {
            printf("%02X ", packet[sizeof(struct ethheader) + (ipv4->iph_ihl * 4) + (TH_OFF(tcp) * 4) + i]);
        }
        printf("\n\n");
    }

    pcap_close(pcap);
    return 0;
}
