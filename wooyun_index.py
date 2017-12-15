# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2017-04-27 14:01:57
# @Last Modified by:   lock
# @Last Modified time: 2017-04-27 16:49:26
import glob
import os
from lxml import etree

def main():
	write_list=set()
	file_list = glob.glob("bugs/*.html")
	for f in file_list:
		with open(f,'r') as fp:
			content = fp.read()
			selector=etree.HTML(content)  #将源码转化为能被XPath匹配的格式
			text = selector.xpath('//*[@id="bugDetail"]/div[@class="content"]/h3[@class="wybug_title"]/text()') #返回为一列表
			for i in text:
				title = i.replace("\t","").strip()
				if title=="":
					continue
				link = "<a href='"+f+"' target='_black'/>"+title+"</a>"
				write_list.add(link)
	with open('index.html','w') as fp:
		for item in write_list:
			fp.write(item.encode('GB2312')+"<br/>")

	print 'all done'

if __name__ == '__main__':
	main()