////////////////////////////////////////////////////////////////////////////////
#include "globals.hpp"
#include "processRawPackets.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <chrono>
////////////////////////////////////////////////////////////////////////////////
using namespace std;

/*
 * Global Packet Statistics
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

/*
 * Globals Initializations
 */
int     _rawSocket;
FILE    *_logfile;
struct  sockaddr_in _source;
struct  sockaddr_in _destination;


int _PACKET_COUNT 	= 10;
int _DST_IP;
int _SRC_IP;
int _DST_PORT		= 17500;
int _SRC_PORT;
bool _CREATE_LOG 	= true;
bool checkPort		= false;
char _DEV[]		= "eno1";

int main()
{
    int socketAddrSize;
	long int dataSize;
    struct sockaddr socketAddr;
    struct in_addr 	in;

    //Allocate Memory for Buffer
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

    //Create a Socket Address to listen on
    if (_CREATE_LOG){
    	_logfile=fopen("log.txt","w");
    	if(_logfile==NULL){
    		printf("Unable to create file.");
    	}
    }
    printf("Starting...\n");

    //Create a raw socket to sniff
    //UDP Sniffer
    //AF_INET   -> IPv4 Protocol
    //SOCK_RAW  -> Raw Network Protocol Access
    //IPPROTO_UDP -> UDP Protocol 
    _rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    //TCP Sniffer
    //_rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    //Bind Socket to dev id
    setsockopt(_rawSocket, SOL_SOCKET , SO_BINDTODEVICE , _DEV , strlen(_DEV)+1);
    
    if(_rawSocket < 0)
    {
        printf("Socket Error.\n");
        return 1;
    }

    while(_PACKET_COUNT>0)
    {
        socketAddrSize = sizeof socketAddr;
        //Receive a packet
        dataSize = recvfrom(
                _rawSocket,                 //sockfd 
                buffer,                     //Buffer
                65536,
                0,
                &socketAddr,
                (socklen_t*)&socketAddrSize
                );

        /*Find the UDP Header
         * ---IP Header
         * ---|UDP Header
         * ---|--|Source Port
         * ---|--|Destination Port
         * ---|--|UDP Length
         * ---|--|UDP Checksum
         * ---|Data Payload
         */
        unsigned short ipHeaderLength;
        struct iphdr *ipHeader = (struct iphdr *)buffer;
        ipHeaderLength = ipHeader->ihl*4;
        struct udphdr *udpHeader = (struct udphdr*)(buffer + ipHeaderLength);
        //ntohs(udpHeader->source);	//Source Port
        //Compare destination port address.
        if (checkPort)
        	if (_DST_PORT == ntohs(udpHeader->dest)){
        	    //High Speed Data Write to log file.
        	    ProcessPacket(buffer, dataSize);
        	    --_PACKET_COUNT;
        }
	else{
	    ProcessPacket(buffer, dataSize);
	    --_PACKET_COUNT;
	}


        if(dataSize <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        //ProcessPacket(buffer , dataSize);
        //--_PACKET_COUNT;
    }
    close(_rawSocket);
    printf("Finished");
    return 0;
};
