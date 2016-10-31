#!/usr/bin/env python

import socket

TCP_IP      = '132.206.126.213'
TCP_PORT    = 5555
BUFFER_SIZE = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)

connection, address = s.accept()
print 'Connection Address:', address
while 1:
    data = connection.recv(BUFFER_SIZE)
    if not data:
        break
    print "Received Data:", data
    connection.send("Got Data")  # echo
connection.close()
