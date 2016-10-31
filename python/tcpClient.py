#!/usr/bin/env python

import socket


TCP_IP = '132.206.126.213'
TCP_PORT = 5555
BUFFER_SIZE = 1024
MESSAGE = "Hello, World!"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send(MESSAGE)
data = s.recv(BUFFER_SIZE)
s.close()

print "Received Data:", data
