# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2016-11-02 17:17:26
# @Last Modified by:   lock
# @Last Modified time: 2016-11-02 18:57:04
import zipfile
import threading
import optparse
def extractFile(zFile, password):
	try:
		zFile.extractall(pwd=password) 
		print("Key Found:", password)
	except: 
		print("start test passwod: "+ password +"\n")
		pass
def main():
	parser = optparse.OptionParser('usage\t -f <zipfile> -d <dictionary> or -h get help')
	parser.add_option('-f', dest='zname', type='string', help='specifyzip file')
	parser.add_option('-d', dest='dname', type='string', help='specifydictionary file')
	options, args = parser.parse_args()
	if options.zname == None or options.dname == None:
		print(parser.usage)
		exit(0) 
	else:
		zname = options.zname
		dname = options.dname 
		zFile = zipfile.ZipFile(zname) 
		dFile = open(dname, 'r')
	for line in dFile.readlines():
		password = line.strip('\n')
		t = threading.Thread(target=extractFile, args=(zFile, password)) 
		t.start()


if __name__ == '__main__': 
	main()