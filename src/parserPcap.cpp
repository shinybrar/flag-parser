////////////////////////////////////////////////////////////////////////////////
/*
 * Author		: Shiny Brar
 * Date Created : October 7, 2016
 * Last Modified: Octopber 13, 2016
 * Purpose		: FPGA Engine Flag Parser
 * Dependencies : pcap
 * Release		: Not Active
 * Version		: 0.1
 * Copyright	: GPL
 */
////////////////////////////////////////////////////////////////////////////////
/*
 *Top Level Module for FPGA Engine UDP Parser. This implementation uses the library
 *libpcap and helper functions in processPacketPcap.h
 */
////////////////////////////////////////////////////////////////////////////////
/* Imports*/
#include <stdio.h>	
#include </usr/include/pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include "globals.hpp"
#include "processPacket.hpp"
/*#include <parserConfig.h>*/
////////////////////////////////////////////////////////////////////////////////
//PCAP Packet Processor
void processPacketPcap(u_char *, const struct pcap_pkthdr *, const u_char *);
////////////////////////////////////////////////////////////////////////////////
/*PCAP Parser
 * Steps involved in the Sniffer
 * 1. Bind to an interface
 * 2. Initialize PCAP, create sniffing session
 * 3. Create sniff parameters and rule set
 * 4. Enter primary execution loop
 * 5. Close session
 */
int main()	
{
/*	printf("Parser Version %d.%d\n",
            parser_VERSION_MAJOR,
            parser_VERSION_MINOR);    */

	/*Variable Declarations*/
	pcap_if_t 	*allDevsPresent;	/*PCAP Interface Type*/
	pcap_if_t 	*device;			
    pcap_t 		*handle;			/*PCAP device handler for the device to be parsed*/
 
    char errbuf[PCAP_ERRBUF_SIZE];
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


	//Start the sniffing loop for n packets, -1 = infinite packets

    pcap_loop(handle , -1 , processPacketPcap, NULL);

    return 0;
}
////////////////////////////////////////////////////////////////////////////////
void processPacketPcap(
		u_char *args,
		const struct pcap_pkthdr *header,
		const u_char *buffer)
{
	using namespace parser;

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
            parser::processPacket().printUdpPacket(buffer, size);
            break;

        default: //Oher Protocol like ARP etc.
            ++_otherPackets;
            break;
    }
    printf("TCP : %f   UDP : %f   ICMP : %f   IGMP : %f   Others : %f   Total : %f\r",
    		_tcpPackets,
			_udpPackets,
			_icmpPackets,
			_igmpPackets,
			_otherPackets,
			_totalPackets);
}
////////////////////////////////////////////////////////////////////////////////
