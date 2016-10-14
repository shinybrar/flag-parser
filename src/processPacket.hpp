/*
 * Author		: Shiny Brar
 * Date Created : October 13, 2016
 * Last Modified: October 13, 2016
 * Purpose		: Class for processing UDP Packets
 * Dependencies : TODO
 * Release		: Not Active
 * Version		: 0.1
 * Copyright	: GPL
 */
////////////////////////////////////////////////////////////////////////////////
#ifndef PROCESS_PACKET_HPP
#define PROCESS_PACKET_HPP
////////////////////////////////////////////////////////////////////////////////
#include <sys/socket.h>
#include <arpa/inet.h> 		/*inet_ntoa: used for parsing ipv4 address*/
#include <net/ethernet.h>	/*Declarations for Ethernet Header*/
#include <netinet/ip_icmp.h>/*Provides declarations for icmp header*/
#include <netinet/tcp.h>   	/*Provides declarations for tcp header*/
#include <netinet/udp.h>   	/*Provides declarations for udp header*/
#include <netinet/ip.h>    	/*Provides declarations for ip header*/
////////////////////////////////////////////////////////////////////////////////
namespace parser
{

class processPacket{
//Public Access Modifiers
public:

	//Default Constructor
	processPacket();

	//Destructor
	virtual ~processPacket();

	//PCAP Packet Processor
	void processPacketPcap(u_char *, const struct pcap_pkthdr *, const u_char *);

	//Raw Socket Packet Processor
	void processPacketRawSocket(unsigned char* buffer, int size);

	//Print Raw Data
	void printData (const u_char * , int);

	//printEthernetHeader
	void printEthernetHeader(const u_char *Buffer, int Size);

	//printIpHeader
	void printIpHeader(const u_char *Buffer, int Size);

	//printUdpPacket
	void printUdpPacket(const u_char * , int);

//Private Access Modifiers
private:
	/*Nothing Here So Far*/

};
} /* Ending processPacket*/
////////////////////////////////////////////////////////////////////////////////
#endif /* PROCESS_PACKET_HPP */
////////////////////////////////////////////////////////////////////////////////

