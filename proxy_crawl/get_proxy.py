#!/usr/bin/env python
# encoding: utf-8
# author: Lock
# time: 2018/1/18 23:21
"""
Have fun, It's Lock
"""

from selenium import webdriver
import time

# 抓取的起始URL
CRAWL_URL = 'http://www.goubanjia.com/free/index.shtml'

# 最多抓取多少页
CRAWL_MAX_PAGE = 1000
# use proxy ,proxy type is http, No proxy please set '' ,
PROXY = ''  # exp: http://127.0.0.1:1087

# config request delay , control request rate
DELAY = True

# scroll screen area, you can change it suit yourself browser
TOP_PX = 280


def get_driver():
    if PROXY:
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument('--proxy-server=%s' % PROXY)
        driver = webdriver.Chrome(chrome_options=chrome_options)
    else:
        driver = webdriver.Chrome()
    return driver


def crawl(driver, url):
    driver.get(url)
    print 'now url is:%s' % (url,)
    driver.execute_script("window.scrollTo(0,%s)" % (TOP_PX,))
    current_page = driver.find_element_by_xpath('//*[@id="list"]/div/span[@class="current"]').text.strip()
    last_page = driver.find_element_by_xpath('//*[@id="list"]/div[@class="wp-pagenavi"]/a[last()]').text.strip()
    driver.save_screenshot('img/%s.png' % (current_page,))
    safe = 1
    while True:
        if safe > CRAWL_MAX_PAGE:
            break
        print 'now crawl page is:%s,last page is:%s' % (current_page, last_page)
        next_page = driver.find_element_by_xpath('//*[@id="list"]/div/span[@class="current"]/following-sibling::a[1]').text.strip()
        current_page = next_page
        last_page = driver.find_element_by_xpath('//*[@id="list"]/div[@class="wp-pagenavi"]/a[last()]').text.strip()
        if current_page == last_page:
            break
        next_page_url = driver.find_element_by_xpath('//*[@id="list"]/div/span[@class="current"]/following-sibling::a[1]').get_attribute('href').strip()
        print 'now url is:%s' % (next_page_url,)
        if next_page_url == '' or next_page_url == False:
            continue
        driver.get(next_page_url)
        driver.execute_script("window.scrollTo(0,%s)" % (TOP_PX,))
        driver.save_screenshot('img/%s.png' % (current_page,))
        if DELAY:
            time.sleep(1)
        safe = safe + 1


if __name__ == '__main__':
    driver = get_driver()
    crawl(driver, CRAWL_URL)
    driver.quit()
    print 'all done'
