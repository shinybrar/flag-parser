using namespace parser;
////////////////////////////////////////////////////////////////////////////////
/*Class Access*/
processPacket::processPacket(){

}

processPacket::~processPacket(){

}
////////////////////////////////////////////////////////////////////////////////
void processPacket::processPacketPcap(
		u_char *args,
		const struct pcap_pkthdr *header,
		const u_char *buffer)
{
    int size = header->len;

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++_totalPackets;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  /*ICMP Protocol*/
            ++_icmpPackets;
            break;

        case 2:  //IGMP Protocol
        	++_igmpPackets;
            break;

        case 6:  //TCP Protocol
            ++_tcpPackets;
            break;

        case 17: //UDP Protocol
            ++ _udpPackets;
            printUdpPacket(buffer , size);
            break;

        default: //Oher Protocol like ARP etc.
            ++_otherPackets;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",
    		_tcpPackets,
			_udpPackets,
			_icmpPackets,
			_igmpPackets,
			_otherPackets,
			_totalPackets);
}
////////////////////////////////////////////////////////////////////////////////
void processPacket::printUdpPacket(
		const u_char *Buffer ,
		int Size)
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
////////////////////////////////////////////////////////////////////////////////
void processPacket::printEthernetHeader(
		const u_char *Buffer,
		int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    printf("\n");
    printf("Ethernet Header\n");
    printf("   |-Destination address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol           : %u \n",(unsigned short)eth->h_proto);
}
////////////////////////////////////////////////////////////////////////////////
void processPacket::printIpHeader(
		const u_char * Buffer,
		int Size)
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
////////////////////////////////////////////////////////////////////////////////
void processPacket::printData(
		const u_char * data ,
		int Size)
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
                {
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                }
                else
                {
                	printf("."); //otherwise print a dot
                }
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
////////////////////////////////////////////////////////////////////////////////
