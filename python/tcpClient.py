#!/usr/bin/env python

import socket

TCP_IP = ''
TCP_PORT = 5555
BUFFER_SIZE = 1024

MESSAGE = '{"runCommand":"./pcapParser -d eth0 -c 10 -p 0 --binary"}'

print("Starting Client...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
print("sending command string")
s.send(MESSAGE)

while True:
    data = s.recv(BUFFER_SIZE)
    while (data):
        sys.stdout.write(buf)
        buf = client.recv(1024)
s.close()

