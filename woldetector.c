#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <net/if.h>

#include <pcap.h>

//global
char *nwinterface;
char *strcommand;

void packet_pro(u_char *user, struct pcap_pkthdr *header, const u_char *packet){

    //get payload addr
    struct ip *iph ;

    u_int size_ether = sizeof(struct ether_header);
    u_int size_ip;
    u_int size_udp = sizeof(struct udphdr);

    u_char *payload ;

    iph = (struct ip *)(packet + size_ether);
    size_ip = 4 * iph->ip_hl;

    payload = (u_char *)(packet + size_ether + size_ip + size_udp);

    //get mac addr
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, nwinterface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    unsigned char *macaddr = ifr.ifr_hwaddr.sa_data;

    //detect my wol packet
    int i;
    int cnt = 0;
    for(i=0; i<6; i++){
        if(payload[i] == 0xFF && macaddr[i] == payload[6+i]){
            cnt++;
        }
    }
    if(cnt == 6){
        //run the command
        system(strcommand);
    }
    fflush(stdout);
}

//main
int main(int argc, char **argv){

    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pd;
    struct bpf_program fcode;
    char filter[] = "udp";
    bpf_u_int32 net;


    //check args
    if(argc <= 2){
        printf("usage : %s <network interface> <unix command>\n ", argv[0]);
        exit(1);
    }

    //pcap init
    pd = pcap_open_live(argv[1],1500,1,1000,ebuf);
    if(pd == NULL){
        fprintf(stderr,"pcap_open_live : %s",ebuf);
        exit(1);
    }
    nwinterface = argv[1];
    strcommand = argv[2];

    //compile filter
    if(pcap_compile(pd, &fcode, filter, 0, net) == -1){
        fprintf(stderr, "pcap_compile : %s\n", filter, pcap_geterr(pd));
        exit(1);
    }

    //set filter
    if (pcap_setfilter(pd, &fcode) == -1) {
        fprintf(stderr, "pcap_setfilter : %s\n", filter, pcap_geterr(pd));
        exit(1);
    }

    //get packet
    if(pcap_loop(pd, -1, packet_pro, NULL) < 0){
        fprintf(stderr, "pcaploop : %s\n", pcap_geterr(pd));
        exit(1);
    }

    pcap_close(pd);
    exit(0);
}