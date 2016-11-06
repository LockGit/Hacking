#!/usr/bin/env python
# encoding: utf-8
# author: Lock
# time: 2016/11/6 15:01
import optparse
import socket
import threading

screenLock = threading.Semaphore(value=1)


def connScan(tgtHost,tgtPort):
    try:
        connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('Hello Lock\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print('[+]%d/tcp open' % tgtPort)
        print('[+] ' + str(results))
    except:
        screenLock.acquire()
        print('[-]%d/tcp closed' % tgtPort)
    finally:
        screenLock.release()
        connSkt.close()


def portScan(tgtHost, tgtPorts):
    """
    多线程 模式
    :param tgtHost:
    :param tgtPorts:
    :return:
    """
    try:
        tgtIP = socket.gethostbyname(tgtHost)
    except:
        print "[-] Cannot resolve '%s': Unknown host" % tgtHost
        return
    try:
        tgtName = socket.gethostbyaddr(tgtIP)
        print('\n[+] Scan Results for: ' + tgtName[0])
    except:
        print('\n[+] Scan Results for: ' + tgtIP)
        socket.setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        print('Scanning port ' + str(tgtPort))
        t = threading.Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()

def run():
    parser = optparse.OptionParser('usage -H < target host > -p < target port > ')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='int', help='specify target port')
    (options, args) = parser.parse_args()
    tgtHost,tgtPort = options.tgtHost,options.tgtPort
    args.append(tgtPort)
    if (tgtHost == None) | (tgtPort == None):
        print('[-] You must specify a target host and port[s]!')
        exit(0)
    portScan(tgtHost, args)


if __name__ == '__main__':
    run()
