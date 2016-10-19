////////////////////////////////////////////////////////////////////////////////
#include "processRawPackets.hpp"
#include "globals.hpp"
////////////////////////////////////////////////////////////////////////////////
using namespace std;
/*
 * Packet Statistics
 */
extern double _tcpPackets;
extern double _udpPackets;
extern double _igmpPackets;
extern double _icmpPackets;
extern double _otherPackets;
extern double _totalPackets;

void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    ++_totalPackets;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++_icmpPackets;
            //PrintIcmpPacket(Buffer,Size);
            break;

        case 2:  //IGMP Protocol
            ++_igmpPackets;
            break;

        case 6:  //TCP Protocol
            ++_tcpPackets;
            print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            ++_udpPackets;
            print_udp_packet(buffer , size);
            break;

        default: //Some Other Protocol like ARP etc.
            ++_otherPackets;
            break;
    }
    printf("TCP : %f   UDP : %f   ICMP : %f   IGMP : %f   Others : %f   Total : %f\r",
    		_tcpPackets,
			_udpPackets,
			_icmpPackets,_igmpPackets,
			_otherPackets,
			_totalPackets);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;

    memset(&_source, 0, sizeof(_source));
    _source.sin_addr.s_addr = iph->saddr;

    memset(&_destination, 0, sizeof(_destination));
    _destination.sin_addr.s_addr = iph->daddr;

    fprintf(_logfile,"\n");
    fprintf(_logfile,"IP Header\n");
    fprintf(_logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(_logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(_logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(_logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(_logfile,"   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(_logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(_logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(_logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(_logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(_logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(_logfile,"   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(_logfile,"   |-Source IP        : %s\n",inet_ntoa(_source.sin_addr));
    fprintf(_logfile,"   |-Destination IP   : %s\n",inet_ntoa(_destination.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);

    fprintf(_logfile,"\n\n***********************TCP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(_logfile,"\n");
    fprintf(_logfile,"TCP Header\n");
    fprintf(_logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(_logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(_logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(_logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(_logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(_logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(_logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(_logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(_logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(_logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(_logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(_logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(_logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(_logfile,"   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(_logfile,"   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(_logfile,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(_logfile,"\n");
    fprintf(_logfile,"                        DATA Dump                         ");
    fprintf(_logfile,"\n");

    fprintf(_logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(_logfile,"TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    fprintf(_logfile,"Data Payload\n");
    PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );

    fprintf(_logfile,"\n###########################################################");
}

void print_udp_packet(unsigned char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);

    fprintf(_logfile,"\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(_logfile,"\nUDP Header\n");
    fprintf(_logfile,"   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(_logfile,"   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(_logfile,"   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(_logfile,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    fprintf(_logfile,"\n");
    fprintf(_logfile,"IP Header\n");
    PrintData(Buffer , iphdrlen);

    fprintf(_logfile,"UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);

    fprintf(_logfile,"Data Payload\n");
    PrintData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));

    fprintf(_logfile,"\n###########################################################");
}

void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);

    fprintf(_logfile,"\n\n***********************ICMP Packet*************************\n");

    print_ip_header(Buffer , Size);

    fprintf(_logfile,"\n");

    fprintf(_logfile,"ICMP Header\n");
    fprintf(_logfile,"   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
        fprintf(_logfile,"  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
        fprintf(_logfile,"  (ICMP Echo Reply)\n");
    fprintf(_logfile,"   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(_logfile,"   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(_logfile,"   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(_logfile,"   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(_logfile,"\n");

    fprintf(_logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(_logfile,"UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);

    fprintf(_logfile,"Data Payload\n");
    PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));

    fprintf(_logfile,"\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
	int i,j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(_logfile,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(_logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(_logfile,"."); //otherwise print a dot
            }
            fprintf(_logfile,"\n");
        }

        if(i%16==0) fprintf(_logfile,"   ");
            fprintf(_logfile," %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(_logfile,"   "); //extra spaces

            fprintf(_logfile,"         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(_logfile,"%c",(unsigned char)data[j]);
                else fprintf(_logfile,".");
            }
            fprintf(_logfile,"\n");
        }
    }
}
