#!/usr/bin/env python

import socket

TCP_IP = 'frb1.physics.mcgill.ca'
TCP_PORT = 5555
BUFFER_SIZE = 1024

MESSAGE = '{"runCommand":"./pcapParser -d eno1 -c 10 -p 0 --binary"}'

print("Starting Client...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
print("sending command string")
s.send(MESSAGE)

size = (s.recv(1024))
print size

rxBuffer=b""
rxBytes = 0
while rxBytes < size:
    data = s.recv(1024)
    if not data:
        break
    if len(data) + rxBlocks > txBlocks:
        data = data[:size-rxBlocks] #Trim additional data
    rxBuffer += data
    rxBlocks += len(data)

with open('packetDataRecv.bin', 'wb') as fd:
    print "Opened Binary Data File"
    f.write(rxBuffer)
    fd.close()

s.close()
