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
int _rawSocket;
FILE *_logfile;
struct sockaddr_in _source;
struct sockaddr_in _destination;

int main()
{
    int socketAddrSize;
	long int dataSize;
    struct sockaddr socketAddr;
    struct in_addr 	in;
    unsigned char 	*buffer = (unsigned char *)malloc(65536); //Its Big!

    _logfile=fopen("log.txt","w");
    if(_logfile==NULL) printf("Unable to create file.");
    printf("Starting...\n");

    //Create a raw socket to sniff
    _rawSocket = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(_rawSocket < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    while(1)
    {
        socketAddrSize = sizeof socketAddr;
        //Receive a packet
        dataSize = recvfrom(_rawSocket , buffer , 65536 , 0 , &socketAddr , (socklen_t*)&socketAddrSize);

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
