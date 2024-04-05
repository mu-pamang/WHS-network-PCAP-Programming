#include <stdio.h>
#include <netinet/in.h>

/* 이더넷 헤더 */
struct EthernetHeader {
    unsigned char destinationMAC[6]; /* 목적지 MAC 주소 */
    unsigned char sourceMAC[6];      /* 출발지 MAC 주소 */
    unsigned short etherType;        /* 이더넷 타입 (IP, ARP, RARP 등) */
};
/* IP 헤더 */
struct IPHeader {
    unsigned char ihl:4,   /* IP 헤더 길이 */
                 version:4; /* IP 버전 */
    unsigned char tos;     /* 서비스 유형 */
    unsigned short totalLength;  /* IP 패킷 길이 (데이터 + 헤더) */
    unsigned short identification; /* 식별자 */
    unsigned short flags:3,   /* 분할 플래그 */
                   offset:13; /* 플래그 오프셋 */
    unsigned char ttl;        /* Time to Live */
    unsigned char protocol;   /* 프로토콜 유형 */
    unsigned short checksum;  /* IP 데이터그램 체크섬 */
    struct in_addr sourceIP;  /* 출발지 IP 주소 */
    struct in_addr destIP;    /* 목적지 IP 주소 */
};
/* ICMP 헤더 */
struct ICMPHeader {
    unsigned char type;     /* ICMP 메시지 유형 */
    unsigned char code;     /* 에러 코드 */
    unsigned short checksum; /* ICMP 헤더와 데이터의 체크섬 */
    unsigned short id;      /* 요청 식별을 위해 사용 */
    unsigned short seq;     /* 순서 번호 */
};
/* TCP 헤더 */
struct TCPHeader {
    unsigned short sourcePort;  /* 출발지 포트 */
    unsigned short destPort;    /* 목적지 포트 */
    unsigned int seqNum;        /* 순서 번호 */
    unsigned int ackNum;        /* 확인 번호 */
    unsigned char offset;       /* 데이터 오프셋, 예약 */
    unsigned char flags;        /* TCP 플래그 */
    unsigned short window;      /* 윈도우 */
    unsigned short checksum;    /* 체크섬 */
    unsigned short urgentPointer; /* 긴급 포인터 */
};
/* Pseudo TCP 헤더 */
struct PseudoTCPHeader {
    unsigned sourceAddr;
    unsigned destAddr;
    unsigned char mbz;
    unsigned char protocol;
    unsigned short tcpl;
    struct TCPHeader tcp;
    char payload[1500];
};

int main() {
    return 0;
}
