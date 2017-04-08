# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2017-02-17 23:36:16
# @Last Modified by:   lock
# @Last Modified time: 2017-04-09 01:45:27
import sys
import zipfile
import itertools
import optparse

def attack(zipFile,passwd):
	try:
		zipFile.setpassword(passwd)
		zipFile.extractall()
		print "The password is: ", passwd
		exit()
	except RuntimeError:
		pass
	except zipfile.BadZipfile:
		pass
	except Exception as e:
		pass

def select_characters(tname):
	if tname=='num':
		return '0123456789'
	if tname=='a':
		return 'abcdefghijklmnopqrstuvwxyz'
	if tname=='A':
		return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	if tname=='aA':
		return 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	if tname=='numa':
		return '1234567890abcdefghijklmnopqrstuvwxyz'
	if tname=='anum':
		return 'abcdefghijklmnopqrstuvwxyz1234567890'
	if tname=='Anum':
		return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
	if tname=='aAnum':
		return 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789'


def main():
	parser = optparse.OptionParser('usage\t -f <zipfile> -t <type> -l <length> or -h get help')
	parser.add_option('-f', dest='zname', type='string', help='specifyzip file')
	parser.add_option('-t', dest='tname', type='string', help='specify type(num|a|A|aA|anum|numa|Anum|aAnum)')
	parser.add_option('-l', dest='length', type='int', help='specify length,default=8',default=8)
	options, args = parser.parse_args()
	if options.zname == None or options.tname == None:
		print(parser.usage)
		exit(0) 
	else:
		zname = options.zname
		tname = options.tname
		length = options.length
		zipFile = zipfile.ZipFile(zname) 
		characters = select_characters(tname)

	for leng in range(1, len(characters)+1):
		print "lenght of password: ", leng
		it = itertools.product(characters, repeat=leng)	
		for pw in it:
			if (len(pw) > length):
				print '当前长度：%s，超过指定长度%s，测试完毕' % (leng,length)
				exit(0)
			attack(zipFile,''.join(pw))

if __name__ == '__main__':
	main()


