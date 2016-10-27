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
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include "globals.hpp"
#include "processPcapPacket.hpp"
#include "parserConfig.hpp"

/*
 * Initializing Global Packet Statistics
 */
double _tcpPackets;
double _udpPackets;
double _igmpPackets;
double _icmpPackets;
double _otherPackets;
double _totalPackets;
double _adcFlags;
double _scalerFlags;
double _fftFlags;
double _totalFlags;

using namespace std;
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
    //TODO:pyConfig.hpp not implemented
    //

    /*Setup Configuration imported from pyConfig.hpp
     *  1. pyDev            <- NIC, e.g. "eth0"
     *  2. pyFilter         <- Port, e.g. "port 41000"
     *  3. pyPacketCount    <- Packets, e.g. 5
     *  4. pyConfig         <- Use python generated config, e.g. true
     */

	printf("\n F-Engine UDP Parser \n Version: %d.%d\n\n",
            parser_VERSION_MAJOR,
            parser_VERSION_MINOR);

	/*Variable Declarations*/
	pcap_if_t 	*allDevsPresent;	/*PCAP Interface Type*/
	pcap_if_t 	*device;			
    pcap_t 		*handle;			/*PCAP device handler for the device to be parsed*/
 
    char    errbuf[PCAP_ERRBUF_SIZE];
    char    *devname; 
    char    devs[100][100];
    int     count = 1;
    int     devNumber;
    int     portNumber;
    bool    pyConfig = false;

    /* 
     * pyConfig not provided, ask user for setup details in terminal.
     */
    if (pyConfig == false){

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
        printf("\nEnter the number of the NIC you want to parse: ");
        scanf("%d" , &devNumber);
        devname = devs[devNumber];

        /*Asking user which port to parse data on*/
        printf("\nEnter the port you want to parse packets on: ");
        scanf("%d", &portNumber);

        /*Asking user how many packets to parse*/
        printf("\nEnter the number of packets to parse: ");
        scanf("%d", &count);
        
    }
    /*
     * pyConfig provided, overide variables.
     */
    if (pyConfig == true){
        //Map Python Generated Configuration
        //devname
        //portNumber
        //count
    }

    /*Attempting to open device and create PCAP handle*/
    printf("Opening NIC %s ...\n", devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "FAILURE, Couldn't open device %s : %s\n", 
        	devname, 
        	errbuf);
        exit(1);
    }
    printf("SUCCESS, parsing on device: %s\n", devname);

    /*
     * Building the Filter to Parse Data
     */
    struct bpf_program filterProgram;                           /* The compiled filter expression */
    char portNum_char =  (char) portNumber;
    char filterExpression[] = strcpy("port ",portNum_char);   /* The filter expression */
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

	//Start the sniffing loop for n packets, -1 = infinite packets

    pcap_loop(handle , 10, processPacketPcap, NULL);

    return 0;
}
////////////////////////////////////////////////////////////////////////////////
void processPacketPcap(
		u_char *args,
		const struct pcap_pkthdr *header,
		const u_char *buffer)
{
    printf("Processing Packed %f\n",_totalPackets);
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
   /* printf("TCP : %f   UDP : %f   ICMP : %f   IGMP : %f   Others : %f   Total : %f\r",
    		_tcpPackets,
			_udpPackets,
			_icmpPackets,
			_igmpPackets,
			_otherPackets,
			_totalPackets);
    */
    printf("Finished Processing\n");
}
////////////////////////////////////////////////////////////////////////////////
