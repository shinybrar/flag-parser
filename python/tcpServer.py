#!/usr/bin/env python
################################################################################

import socket
import os
import sys
import json
import subprocess

################################################################################
def changeDir():
    #Moving into build directory
    os.chdir("../build/")
    if (not os.path.isfile('pcapParser')):
        print "ERROR: Could not find file pcapParser in ../build directory.\
            Build the project before running the TCP Server"
        exit()
################################################################################
def startServer( ip, port, buffer ):
    #TCP Socket Parameters - Change as Needed
    TCP_IP      = ip  	# '' Symbolic name, meaning all available interfaces
    TCP_PORT    = port
    BUFFER_SIZE = buffer

    #Creating a TCP Socket
    print "Starting TCP Server\n"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))

    #Start Listening with a backlog of 5 connections
    s.listen(5) 

    print("Server started, listening ...")
    while True:
        #Accepting Connections
        connection, address = s.accept()

        # Example JSON string command
        # '{"runCommand":"./pcapParser -d eth0 -c 10 -p 0 --binary"}'

        print 'Connection Address: ', address
        while True:
            data = connection.recv(BUFFER_SIZE)
            if not data:
                break
            #Load the JSON Data
            jsonString = json.loads(data)
            print "Received Command:", data
    
            #Run the JSON Command
            process = subprocess.call(jsonString['runCommand'], shell=True)

            if (not os.path.isfile('packetData.bin')):
                connection.send("ERROR: Could not find file packetData.bin")

            fd = open("packetData.bin","rb") 	#Open file in binary
	    binData = fd.read(1024)
	    while (binData):
	        s.send(binData)
                binData = fd.read(1024)
	#Terminate Current Connection but keep the server going.  
        connection.close()
################################################################################
if __name__ == "__main__":
    changeDir()
    startServer('', 5555, 1024)
