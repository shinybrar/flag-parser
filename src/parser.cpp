/**
Top Level Module for FPGA Engine UDP Parser.

Implementations:
	1. libpcap
	2. Raw Socket
	3. DPDK
*/

/* Imports*/
#include <stdio.h>	
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
/*#include <parserConfig.h>*/
 
#include <sys/socket.h>
#include <arpa/inet.h> 		/*inet_ntoa: used for parsing ipv4 address*/
#include <net/ethernet.h>	/*Declarations for Ethernet Header*/
#include <netinet/ip_icmp.h>/*Provides declarations for icmp header*/
#include <netinet/tcp.h>   	/*Provides declarations for tcp header*/
#include <netinet/udp.h>   	/*Provides declarations for udp header*/
#include <netinet/ip.h>    	/*Provides declarations for ip header*/

void processPacket(u_char *, const struct pcap_pkthdr *, const u_char *);
void printEthernetHeader(const u_char *Buffer, int Size);
void printIpHeader(const u_char *Buffer, int Size);
void printUdpPacket(const u_char * , int);
void printData (const u_char * , int);

/* PCAP Parser
Steps involved in the Sniffer
1. Bind to an interface
2. Initialize PCAP, create sniffing session
3. Create sniff parameters and rule set
4. Enter primary execution loop
5. Close session
*/

struct sockaddr_in source;
struct sockaddr_in dest;
int tcp=0;
int udp=0;
int icmp=0;
int others=0;
int igmp=0;
int total=0;
int i,j;


/*Main Function*/
int main()	
{

/*	printf("Parser Version %d.%d\n",
            parser_VERSION_MAJOR,
            parser_VERSION_MINOR);    */

	/*Variable Declarations*/
	pcap_if_t 	*allDevsPresent;	/*PCAP Interface Type*/
	pcap_if_t 	*device;			
    pcap_t 		*handle;			/*PCAP device handler for the device to be parsed*/
 
    char errbuf[100];
    char *devname; 
    char devs[100][100];
    int count = 1;
    int n;

	/*Looking for all available devices. */
	printf("Finding available Network Interface Devices ...");
    if( pcap_findalldevs( &allDevsPresent , errbuf) )
    {
        printf("Error finding devices : %s", 
        	errbuf);
        exit(1);
    }
    printf("Done");
     
    /*Displaying available devices*/
    printf("\nAvailable NIC(s) :\n");
    for(device = allDevsPresent; device != NULL; device = device->next)
    {
        printf("%d. %s - %s\n", 
        	count, 
        	device->name, 
        	device->description);

        if(device->name != NULL)
        {
            strcpy(devs[count], device->name);
        }
        count++;
    }

    /*Asking user which device to bind on*/
    printf("Enter the number of the NIC you want parsed : ");
    scanf("%d" , &n);
    devname = devs[n];
     
    /*Attempting to open device and create PCAP handle*/
    printf("Opening NIC %s for parsing ... ", 
    	devname);
    
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
     
    if (handle == NULL) 
    {
        fprintf(stderr, "Failure, Couldn't open device %s : %s\n", 
        	devname, 
        	errbuf);
        exit(1);
    }
    printf("Success, parsing on device: %s\n", devname);


	//Start the sniffing loop
    pcap_loop(handle , -1 , processPacket , NULL);

    return 0;
}

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
     
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  /*ICMP Protocol*/
            ++icmp;
            break;
         
        case 2:  //IGMP Protocol
        	++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            break;
         
        case 17: //UDP Protocol
            ++udp;
            printUdpPacket(buffer , size);
            break;
         
        default: //Oher Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

void printUdpPacket(const u_char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
  
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    printf("\n***********************UDP Packet*************************\n");
     
    printIpHeader(Buffer,Size);        
     
    printf("\nUDP Header\n");
    printf("   |-Source Port     	: %d\n" , ntohs(udph->source));
    printf("   |-Destination Port 	: %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       	: %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     	: %d\n" , ntohs(udph->check));
     
    printf("\n");
    printf("IP Header\n");
    printData(Buffer , iphdrlen);
         
    printf("UDP Header\n");
    printData(Buffer+iphdrlen , sizeof udph);
         
    printf("Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    printData(Buffer + header_size , Size - header_size);
     
    printf("\n##########################################################\n");
}

void printEthernetHeader(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    printf("\n");
    printf("Ethernet Header\n");
    printf("   |-Destination address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol           : %u \n",(unsigned short)eth->h_proto);
}

void printIpHeader(const u_char * Buffer, int Size)
{
    printEthernetHeader(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    printf("\n");
    printf("IP Header\n");
    printf("   |-IP Version        	: %d\n",(unsigned int)iph->version);
    printf("   |-IP Header Length  	: %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("   |-Type Of Service   	: %d\n",(unsigned int)iph->tos);
    printf("   |-IP Total Length   	: %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf("   |-Identification    	: %d\n",ntohs(iph->id));
    printf("   |-TTL      		: %d\n",(unsigned int)iph->ttl);
    printf("   |-Protocol 		: %d\n",(unsigned int)iph->protocol);
    printf("   |-Checksum 		: %d\n",ntohs(iph->check));
    printf("   |-Source IP        	: %s\n" , inet_ntoa(source.sin_addr) );
    printf("   |-Destination IP   	: %s\n" , inet_ntoa(dest.sin_addr) );
}

void printData (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf("   "); //extra spaces
            }
             
            printf("         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  printf("%c",(unsigned char)data[j]);
                }
                else
                {
                  printf(".");
                }
            }
            printf("\n" );
        }
    }
}