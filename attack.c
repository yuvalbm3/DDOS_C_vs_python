
#include <stdio.h>	//for printf
#include <string.h> //memset
#include <sys/socket.h>	//for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <stdint.h>
#include <time.h>


/* 
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int main (void) {
    FILE *fptr;
    //Create a raw socket
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    if (s == -1) {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }

    //Datagram to represent the packet
    char datagram[4096], source_ip[32], *data, *pseudogram;

    //zero out the packet buffer
    memset(datagram, 0, 4096);

    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;

    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

    double* ptr;
    int n = 1000000;

    // Dynamically allocate memory using malloc()
    ptr = (double*)malloc(n * sizeof(double));

    if (ptr == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }
    else{
        //File open
        fptr = fopen("syns_results_c.txt", "w");

        if (fptr == NULL) {
            printf("Can't open this file!");
        }

        long start_t = clock();
        for (int fl = 0; fl < 100; fl++) {
            for (int jk = 0; jk < 10000; jk++) {
                char buffer_write[256];
                //some address resolution
                char ipsrc[16];
                int num[4];
                int i;
                for (i = 0; i < 4; i++) {
                    num[i] = (rand() % (256));
                }
                sprintf(ipsrc, "%d.%d.%d.%d", num[0], num[1], num[2], num[3]);
                long start_packet = clock();
                strcpy(source_ip, ipsrc);
                sin.sin_family = AF_INET;
                sin.sin_port = htons(80);
                sin.sin_addr.s_addr = inet_addr("10.0.2.15");

                //Fill in the IP Header
                iph->ihl = 5;
                iph->version = 4;
                iph->tos = 0;
                iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
                iph->id = htonl(54321);    //Id of this packet
                iph->frag_off = 0;
                iph->ttl = 255;
                iph->protocol = IPPROTO_TCP;
                iph->check = 0;        //Set to 0 before calculating checksum
                iph->saddr = inet_addr(source_ip);    //Spoof the source ip address
                iph->daddr = sin.sin_addr.s_addr;

                //Ip checksum
                iph->check = csum((unsigned short *) datagram, iph->tot_len);
                //Generate random src port
                int src = (rand() % (55600));
                //TCP Header
                tcph->source = htons(src);
                tcph->dest = htons(80);
                tcph->seq = 0;
                tcph->ack_seq = 0;
                tcph->doff = 5;    //tcp header size
                tcph->fin = 0;
                tcph->syn = 1;
                tcph->rst = 0;
                tcph->psh = 0;
                tcph->ack = 0;
                tcph->urg = 0;
                tcph->window = htons(5840);    /* maximum allowed window size */
                tcph->check = 0;    //leave checksum 0 now, filled later by pseudo header
                tcph->urg_ptr = 0;

                //Now the TCP checksum
                psh.source_address = inet_addr(source_ip);
                psh.dest_address = sin.sin_addr.s_addr;
                psh.placeholder = 0;
                psh.protocol = IPPROTO_TCP;
                psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

                int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
                pseudogram = malloc(psize);

                memcpy(pseudogram, (char *) &psh, sizeof(struct pseudo_header));
                memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));

                tcph->check = csum((unsigned short *) pseudogram, psize);

                //IP_HDRINCL to tell the kernel that headers are included in the packet
                int one = 1;
                const int *val = &one;

                if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
                    perror("Error setting IP_HDRINCL");
                    exit(0);
                }
                //Send the packet
                if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
                    perror("sendto failed");
                }
                    //Data send successfully
                else {
                    long end_packet = clock();
                    double diff_packet_time = (double) (end_packet - start_packet) / CLOCKS_PER_SEC;
                    sprintf(buffer_write, "%d. Time for packet: %lf\n", ((fl * 10000) + (jk + 1)), diff_packet_time);
                    fprintf(fptr, "%s", buffer_write);
                    ptr[(fl * 10000) + (jk + 1)] = diff_packet_time;
                    if (jk % 5000 == 0) {
                        printf("%d, %lf\n", ((fl * 10000) + (jk + 1)), diff_packet_time);
                    }
                }
            }
        }
        char buffer_write2[256];
        char buffer_average[256];
        long end_t = clock();
        //Average packet RTT
        float sum;
        int loop;
        float avg;
        sum = avg = 0;
        for(loop = 0; loop < n; loop++) {
            sum += ptr[loop];
        }
        avg = sum / loop;
        printf("Average of array values is %.17f\n", avg);
        sprintf(buffer_average, "Average %.17f\n", avg);
        fprintf(fptr, "%s", buffer_average);
        double diff_total_time = (double)(end_t - start_t)/CLOCKS_PER_SEC;
        sprintf(buffer_write2, "Total  %lf\n", diff_total_time);
        fprintf(fptr, "%s", buffer_write2);
        fclose(fptr);
        return 0;
    }
}

