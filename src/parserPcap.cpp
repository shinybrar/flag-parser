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
 * parserConfig.hpp
 * globals.hpp
 */
////////////////////////////////////////////////////////////////////////////////
/* 
 * Imports
 */
#include <stdio.h>	
#include <getopt.h>
#include <pcap.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <sstream>
#include "globals.hpp"
#include "processPcapPacket.hpp"
#include "parserConfig.hpp"

#define STATIC_BINARY_FILENAME "packetData.bin"

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
 *Help Menu for Command Line Parser
 */
void usage()
{
    printf("\nF-Engine UDP Packet Parser\n");
    printf( "Valid Options:\
            \nUSER FLAGS:\
            \n[--help,-h]   Prints this message\
            \n[--verbose]   Configures parser in verbose mode\
            \n[--binary]    Creates a binary data dump file\
            \n[--terminal]  Runs the user through configuration on the terminal\
            \n[--stat]      Prints the packets statistics at the end of capture\
            \nUSER OPTIONS:\
            \n[--dev,-d]    NIC to grab packets from, e.g. eth0\
            \n[--port,-p]   Port to grab packets from, e.g. 5555\
            \n              DEFAULT: -p 0 results in all packets\
            \n[--count,-c]  Number of packets to parse, e.g. 10\
            \n              NOTE: -c 0 grabs infinite packets\
            \nEXAMPLE:\
            \n./parserPcap --binary -d eno0 -p 41000 -c 5\n");
}
////////////////////////////////////////////////////////////////////////////////
/*
 * PCAP Packet Processor
 */
void processPacketPcap(u_char *, const struct pcap_pkthdr *, const u_char *);

////////////////////////////////////////////////////////////////////////////////
/*
 * PCAP Packet Dump
 */
void packetDump(u_char *dumpFile, const struct pcap_pkthdr *header, const u_char *buffer);

////////////////////////////////////////////////////////////////////////////////

/* Runtime Operation Flags */
static int binaryFlag;          /* Creates a binary data file dump */
static int verboseFlag;         /* Prints Packet data to terminal */
static int terminalFlag;        /* Runs the user through setup through terminal */
static int statisticsFlag;      /* Prints the stats of all packets seen during a capture */

int main (int argc, char **argv)
{   
    /*
     * Parse Command Line Options
     */

    /* Default values for options*/
    char*   devid = NULL;
    int     count = 5;
    int     port = 0;
    int     c;
    while (1)
    {
        static struct option long_options[] =
        {
            /* These options set a flag. */
            {"verbose", no_argument,    &verboseFlag, 1},
            {"binary",  no_argument,    &binaryFlag,  1},
            {"terminal",no_argument,    &terminalFlag,1},
            {"stat",    no_argument,    &statisticsFlag,1},
            /* These options don’t set a flag.
            We distinguish them by their indices. */
            {"help",    no_argument,       0, 'h'},
            {"dev",     required_argument, 0, 'd'},
            {"count",   required_argument, 0, 'c'},
            {"port",    required_argument, 0, 'p'},
            {0, 0, 0, 0}
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;
        c = getopt_long (argc, argv, "hc:d:p:", long_options, &option_index);
      
        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c)
        {
            case 0:
                /* If this option set a flag, do nothing else now. */
                if (long_options[option_index].flag != 0)
                    break;
                printf ("option %s", long_options[option_index].name);
                if (optarg)
                    printf (" with arg %s", optarg);
                printf ("\n");
                break;

            case 'h':
                usage();
                exit(0);

            case 'd':
                devid = optarg;
                break;

            case 'c':
                count = (int)atoi(optarg);
                break;

            case 'p':
                port = (int)atoi(optarg);
                break;

            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                abort ();
        }
    }

    /* --Verbose Flag turns on printf*/
    if (verboseFlag){
        printf("\nParser Configuration Details:\n");
        if (verboseFlag)
            printf ("VERBOSE: ON\n");
        if (binaryFlag)
            printf ("BINARY : ON\n");
    
        printf ("DEV ID : %s\n", devid);
        printf ("PACKETS: %i\n", count);
        printf ("PORT   : %i\n", port);
        printf ("Version: %d.%d\n\n", parser_VERSION_MAJOR, parser_VERSION_MINOR);
    }
    /* Print any remaining command line arguments (not options). */
    if (optind < argc)
    {
        printf ("non-option ARGV-elements: ");
        while (optind < argc)
            printf ("%s ", argv[optind++]);
    }


    /* Setup Configuration Parameters for PCAP
     *  1. dev          <- NIC, e.g. "eth0"         <-- Mapped from --dev,-d
     *  2. portFilter   <- Port, e.g. "port 41"     <-- Mapped from --port,-p 
     *  3. packetCount  <- Packets, e.g. 5          <-- Mapped from --count, -c
     *  4. binaryFile   <- Create Binary File       <-- Mapped from --binary
     */

    /*
     * PCAP Parser
     * Steps involved in the Sniffer
     * 1. Bind to an interface
     * 2. Initialize PCAP, create sniffing session
     * 3. Create sniff parameters and rule set
     * 4. Enter primary execution loop
     * 5. Close session
     */

	/*Variable Declarations for PCAP*/
	pcap_if_t 	    *allDevsPresent;	/*PCAP Interface Type for all devices*/
	pcap_if_t 	    *device;			/*Device of interest to bind on*/
    pcap_t 		    *handle;			/*PCAP device handler for the device to be parsed*/
    pcap_dumper_t   *dumpFile;          /*PCAP pointer to the dump file */
 
    char    errbuf[PCAP_ERRBUF_SIZE];
    char    *devname; 
    char    devs[100][100];
    int     devNumber;

    if (terminalFlag)
    {
        /*Looking for all available devices*/
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
        printf("\nEnter NIC # to bind: ");
        scanf("%d" , &devNumber);
        devname = devs[devNumber];

        /*Asking user which port to parse data on*/
        printf("\nEnter port to capture packets on, e.g. 41000, \nNOTE: port 0 returns all packets: ");
        scanf("%d", &port);

        /*Asking user how many packets to parse*/
        printf("\nEnter the number of packets to capture, e.g. 10: ");
        scanf("%d", &count);
    }
    else{
        /*Setup settinsg based on command-line parser*/
        /*Port and Count already handled separately*/
        devname = devid;
    }


    /* 
     * PCAP Parser
     */

    /*Attempting to open device and create PCAP handle*/
    printf("Opening NIC: %s\n", devname);
    handle = pcap_open_live(devname,    //Name of Device 
                            65536,      //Packet Buffer Size
                            1,          //Promiscous Mode ON
                            0,          //User
                            errbuf);    //Error String Returned by PCAP
    if (handle == NULL) 
    {
        printf("FAILURE: Could not open device %s : %s\n", devname, errbuf);
        exit(1);
    }
    printf("SUCCESS: Capturing packets on device: %s\n", devname);

    if (port != 0){
        /*
         * Building the Filter to Capture Data based on port number
         * The port filter has to be in the form char[] = "port 22"
         */
        stringstream filterSS;                  
        filterSS << "port " << port; 
        string filter = filterSS.str();
        char* filterExpression = new char[filter.length() + 1];
        copy(filter.c_str(), filter.c_str() + filter.length() + 1, filterExpression); 
        struct bpf_program filterProgram;           /* The compiled filter expression */
        //bpf_u_int32 mask;                           /* The netmask of our sniffing device */
        bpf_u_int32 net;                            /* The IP of our sniffing device */

        /*Compile Filter*/
        if (pcap_compile(handle, &filterProgram, filterExpression, 1, net) == -1) {
            printf("Couldn't parse filter%s: %s\n",filterExpression, pcap_geterr(handle));
            return(2);
        }

        /*Apply Filter to PCAP handle*/
        if (pcap_setfilter(handle, &filterProgram) == -1) {
            printf("Couldn't install filter %s: %s\n",filterExpression, pcap_geterr(handle));
            return(2);
        }
    }

	/*
     * Start the sniffing loop for --count packets
     * NOTE: when count = -1, infinite packets are sniffed
     */
    if (binaryFlag)
    {
        //Create a Binary Data Dump File
        //Static Filename = packets.bin
        

        char filename[80]; 
        strcpy(filename, STATIC_BINARY_FILENAME);
        int pcount;
        
        if ((dumpFile = pcap_dump_open(handle,filename)) == NULL) {
            /*
             * Print out error message if pcap_dump_open failed. This will
             * be the below message followed by the pcap library error text,
             * obtained by pcap_geterr().
             */
            printf("Error opening savefile \"%s\" for writing: %s\n", filename, pcap_geterr(handle));
            exit(1);
        }

        /* Start capture to Dump File */
        pcap_loop(handle, count, packetDump, (unsigned char *)dumpFile);

        printf("Packets received and successfully passed through filter: %d.\n",pcount);
        /*
         * Close the savefile opened in pcap_dump_open().
         */
        pcap_dump_close(dumpFile);
    }
    else
    {
        pcap_loop(handle , count, processPacketPcap, NULL);
    }
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
            if (verboseFlag)
            {
                processPacket().printUdpPacket(buffer, size);
            }
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

/* Callback function invoked by libpcap for every incoming packet */
void packetDump(u_char *dumpFile, const struct pcap_pkthdr *header, const u_char *buffer)
{
    /* Save the packet on the dump file */
    pcap_dump(dumpFile, header, buffer);
}

////////////////////////////////////////////////////////////////////////////////
