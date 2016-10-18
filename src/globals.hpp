////////////////////////////////////////////////////////////////////////////////
#ifndef GLOBALS_HPP
#define GLOBALS_HPP
////////////////////////////////////////////////////////////////////////////////
using namespace std;

/*Global Declarations*/
#include <stdio.h> 				/*Standard needed tools*/
#include <stdlib.h>    			/*malloc*/
#include <string.h>    			/*memset*/
#include <netinet/ip_icmp.h>   	/*ICMP Header Definition*/
#include <netinet/udp.h>   		/*UDP Header*/
#include <netinet/tcp.h>   		/*TCP Header*/
#include <netinet/ip.h>    		/*IP Layer Header*/
#include <sys/socket.h>			/*Raw Socket*/
#include <arpa/inet.h>
#include <unistd.h>

/*
 * Packet Statistics
 */
extern double _tcpPackets;
extern double _udpPackets;
extern double _igmpPackets;
extern double _icmpPackets;
extern double _otherPackets;
extern double _totalPackets;

/*
 * FPGA Flag Statistics
 */
extern double _adcFlags;
extern double _scalerFlags;
extern double _fftFlags;
extern double _totalFlags;

extern int _rawSocket;
extern FILE *_logfile;

/*Structure for Handling Internet Addresses*/
/*struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};
struct in_addr {
    unsigned long s_addr;  // load with inet_aton() <- converts from dot/strings to numbers
};*/
extern struct sockaddr_in _source;
extern struct sockaddr_in _destination;
////////////////////////////////////////////////////////////////////////////////
#endif
