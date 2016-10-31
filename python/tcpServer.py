#!/usr/bin/env python
################################################################################

import socket
import os
import sys
import json
import subprocess
from sendfile import sendfile

################################################################################

#Moving into build directory
os.chdir("../build/")
if (not os.path.isfile('pcapParser')):
    print "ERROR: Could not find file pcapParser in ../build directory.\
            Build the project before running the TCP Server"
    exit()
################################################################################

#TCP Socket Parameters - Change as Needed
TCP_IP      = ''    # Symbolic name, meaning all available interfaces
TCP_PORT    = 5555
BUFFER_SIZE = 1024

################################################################################

#Creating a TCP Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))

#Start Listening with a backlog of 1 connections
s.listen(1)

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

        fd = open("packetData.bin","rb")
        blocksize = os.path.getsize("packetData.bin")
        offset = 0

        while True:
            sent = sendfile(s.fileno(), fd.fileno(), offset, blocksize)
            if sent == 0:
                break  # EOF
        offset += sent
        
        # with open("packetData.bin", "rb") as fd:
        #     buf = fd.read(1024)
        #     while (buf):
        #         s.send(buf)
        #         buf = fd.read(1024)  
        connection.close()
