#!/usr/bin/env python
# -*- coding: utf-8 -*-

'a socket test which send message to server.'

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8080))
print (s.recv(1024))
for data in ['Michael', 'Tracy', 'Sarah']:
    s.send(data.encode("utf-8"))
    print (s.recv(1024))
    print("start")
s.send('exit'.encode("utf-8"))
s.close()
