////////////////////////////////////////////////////////////////////////////////

/*
 * Author		: Shiny Brar
 * Date Created : October 7, 2016
 * Last Modified: Octopber 28, 2016
 * Purpose		: FPGA Engine Flag Parser
 * Dependencies : pcap
 * Release		: Not Active
 * Version		: 0.1
 * Copyright	: GPL
 */

////////////////////////////////////////////////////////////////////////////////

/*
 * Top Level Module for FPGA Engine UDP Parser. 
 * This implementation uses the library libpcap and helper functions in 
 * processPacketPcap.h
 * optionparser.h
 * parserConfig.hpp
 * globals.hpp
 */

////////////////////////////////////////////////////////////////////////////////

/* Imports*/
#include <stdio.h>	
#include <pcap.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <sstream>
#include "globals.hpp"
#include "processPcapPacket.hpp"
#include "parserConfig.hpp"

////////////////////////////////////////////////////////////////////////////////

/*
 * Global Packet Statistics
 */
double _tcpPackets;
double _udpPackets;
double _igmpPackets;
double _icmpPackets;
double _otherPackets;
double _totalPackets;

/*
 * Global Flag Statistics
 */
double _adcFlags;
double _scalerFlags;
double _fftFlags;
double _totalFlags;
////////////////////////////////////////////////////////////////////////////////

using namespace std;

////////////////////////////////////////////////////////////////////////////////

/*
 * PCAP Packet Processor*/
void processPacketPcap(u_char *, const struct pcap_pkthdr *, const u_char *);

////////////////////////////////////////////////////////////////////////////////

/*

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

    /* Setup Configuration Parameters
     *  1. dev          <- NIC, e.g. "eth0"
     *  2. portFilter   <- Port, e.g. "port 41000"
     *  3. packetCount  <- Packets, e.g. 5
     *  4. binaryFile   <- Binary dump file creation, e.g. true
     *  5. filename     <- Name of binary dump file, e.g. "packets.bin"
     */

	printf("\n F-Engine Packet Parser \n Version: %d.%d\n\n",
            parser_VERSION_MAJOR,
            parser_VERSION_MINOR);

	/*Variable Declarations*/
	pcap_if_t 	*allDevsPresent;	/*PCAP Interface Type for all devices*/
	pcap_if_t 	*device;			/*Device of interest to bind on*/
    pcap_t 		*handle;			/*PCAP device handler for the device to be parsed*/
 
    char    errbuf[PCAP_ERRBUF_SIZE];
    char    *devname; 
    char    devs[100][100];
    int     count = 1;
    int     devNumber;
    int     portNumber;

    /*Looking for all available devices. */
    printf("Finding available Network Interface Devices ... ");
    if( pcap_findalldevs( &allDevsPresent , errbuf) )
    {
        printf("Error finding devices : %s\n",errbuf);
        exit(1);
    }
    printf("Done\n");
     
    /*Displaying available devices*/
    printf("Available NIC(s) :\n");
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
    printf("\nEnter NIC to bind : ");
    scanf("%d" , &devNumber);
    devname = devs[devNumber];

    /*Asking user which port to parse data on*/
    printf("\nEnter port to capture packets on, e.g. 41000, \nNOTE: port 0 returns all packets: ");
    scanf("%d", &portNumber);

    /*Asking user how many packets to parse*/
    printf("\nEnter the number of packets to capture, e.g. 10: ");
    scanf("%d", &count);
        
    /*Attempting to open device and create PCAP handle*/
    printf("Opening NIC: %s\n", devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
    if (handle == NULL) 
    {
        printf("FAILURE: Could not open device %s : %s\n", 
        	devname, 
        	errbuf);
        exit(1);
    }
    printf("SUCCESS: Capturing packets on device: %s\n", devname);

    if (portNumber != 0){
        /*
         * Building the Filter to Capture Data
         * The port filter has to be in the form char[] = "port 22"
         */
        stringstream filterSS;                  
        filterSS << "port " << portNumber; 
        string filter = filterSS.str();
        char* filterExpression = new char[filter.length() + 1];
        copy(filter.c_str(), filter.c_str() + filter.length() + 1, filterExpression); 


        struct bpf_program filterProgram;                           /* The compiled filter expression */
        //char* filterExpression[ ] = filter.str().c_str();         /* The filter expression */
        bpf_u_int32 mask;                                           /* The netmask of our sniffing device */
        bpf_u_int32 net;                                            /* The IP of our sniffing device */

        if (pcap_compile(handle, &filterProgram, filterExpression, 1, net) == -1) {
            printf("Couldn't parse filter%s: %s\n",filterExpression, pcap_geterr(handle));
            return(2);
        }

        if (pcap_setfilter(handle, &filterProgram) == -1) {
            printf("Couldn't install filter %s: %s\n",filterExpression, pcap_geterr(handle));
            return(2);
        }
    }

	//Start the sniffing loop for n packets, -1 = infinite packets

    pcap_loop(handle , count, processPacketPcap, NULL);

    return 0;
}
////////////////////////////////////////////////////////////////////////////////
void processPacketPcap(
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
            processPacket().printUdpPacket(buffer, size);
            break;

        default: //Other Protocol like ARP etc.
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
