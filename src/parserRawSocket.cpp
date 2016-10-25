////////////////////////////////////////////////////////////////////////////////
#include "globals.hpp"
#include "processRawPackets.hpp"
////////////////////////////////////////////////////////////////////////////////
using namespace std;

/*
 * Packet Statistics
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
 * Globals
 */
int     _rawSocket;
FILE    *_logfile;
struct  sockaddr_in _source;
struct  sockaddr_in _destination;
bool    _createLog;


int main()
{
    int socketAddrSize;
	long int dataSize;
    struct sockaddr socketAddr;
    struct in_addr 	in;
    //Buffer Pointer
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

    _logfile=fopen("log.txt","w");
    if(_logfile==NULL){
        printf("Unable to create file.");
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
    
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
    
    //
    if(_rawSocket < 0)
    {
        printf("Socket Error.\n");
        return 1;
    }
    while(1)
    {
        socketAddrSize = sizeof socketAddr;
        //Receive a packet
        dataSize = recvfrom(
                _rawSocket,                 //sockfd 
                buffer,                     //
                65536,
                0,
                &socketAddr,
                (socklen_t*)&socketAddrSize
                );

        if(dataSize <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(buffer , dataSize);
    }
    close(_rawSocket);
    printf("Finished");
    return 0;
};
