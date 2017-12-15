# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2017-12-15 18:23:22
# @Last Modified by:   lock
# @Last Modified time: 2017-12-16 00:41:42
import requests  
from lxml import html  
import sys  
import urlparse
import collections
import time
from PIL import Image
import os
import random
 
URL = "https://www.xxx.top" # 要爬取的网站

# 爬取的URL域名范围
URL_RULE = [
	'https://www.xxx.top',
	'https://xxx.top',
	'http://www.xxx.top',
	'http://xxx.top'
]

# 存储图片目录
CRAWL_IMAGES_DIR = 'crawl_images'
 
# 根据图片大小过滤，单位像素,小于这个像素的不要
WIDTH = 30
HEIGHT = 30
 

###########################################################
# 抓取url队列
url_queue = collections.deque()
url_queue.append(URL)
 
# 抓取过的url
url_crawled = set()
url_crawled.add(URL)
 
# 抓取过的图片url
url_image = set()
 
# 单线程抓取
while(len(url_queue)):
	print("Url queue length is %d" % len(url_queue))
 
	url = url_queue.popleft()
 
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
	response = requests.get(url, headers = headers)
	content_body = html.fromstring(response.content)
 
	parsed_body = html.fromstring(response.text)
	images = parsed_body.xpath('//img/@src')
 
	images = {urlparse.urljoin(response.url, url) for url in images}
	print "Found %d image in %s" % (len(images), url)
 
	# 下载图片
	for image in images - url_image:
		try:
			r = requests.get(image, headers = headers,timeout=10)
			filename = image.split('/')[-1]
			now = time.localtime(time.time())
			year, month, day, hour, minute, second, weekday, yearday, daylight = now
			if os.path.exists(CRAWL_IMAGES_DIR)==False:
				os.makedirs(CRAWL_IMAGES_DIR)

			file_path = "%s/" %(CRAWL_IMAGES_DIR,) + "%02d-%02d-%02d-" % (year, month, day) + "%02d:%02d:%02d-" % (hour, minute, second) + filename
	 
			with open(file_path,'w') as f:
				f.write(r.content)

			img = Image.open(file_path)
			width = img.size[0]
			height = img.size[1]
			if width <= WIDTH or height <= HEIGHT:
				os.remove(file_path)
			else:
				print file_path
 
			url_image.add(image)
 
			time.sleep(random.randint(1,2))
		except IOError:
			print "can not open image"
		except Exception, e:
			print e.message
 
 
	# 获取网页上所有url
	links = {urlparse.urljoin(response.url, url) for url in content_body.xpath('//a/@href') if urlparse.urljoin(response.url, url).startswith('http')}
	
	for link in links - url_crawled:
		for url_rule in URL_RULE:
			if link.startswith(url_rule) is True:
				url_crawled.add(link)
				url_queue.append(link)
 
	time.sleep(random.randint(1,2))


print 'all done'

