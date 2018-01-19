#!/usr/bin/env python
# encoding: utf-8
# author: Lock
# time: 2018/1/19 11:01
"""
Have fun, It's Lock
"""

from PIL import Image
import pytesseract
import glob


# 图片识别，cpu密集型，测试多线程效果不是很好，这里是单一进程
# 可以裁剪后识别提高速度

def get_all_png():
    png_list = glob.glob("img/*.png")
    return png_list


def ocr(img_path):
    img_res = pytesseract.image_to_string(Image.open(img_path), lang='chi_sim')
    img_arr = img_res.split('\n')
    with open('proxy.md', 'a') as fp:
        for item in img_arr:
            if item == '' or item == False:
                continue
            if '匿名度' in img_arr or '响应速度' in item:
                continue
            line_arr = item.split(' ')
            if len(line_arr) >= 3:
                proxy = line_arr[0].replace('Z', '2').replace('l', '1').replace('O', '0').replace('o', '0')
                if ':' not in proxy:
                    continue
                proxy_anonymous = line_arr[1].replace('董', '匿').replace('堇', '匿').replace('国', '匿').replace('匡', '匿')
                proxy_type = line_arr[2].lower().replace('′', ',')
                print '[*] find proxy server:%s,%s,%s' % (proxy, proxy_anonymous, proxy_type)
                fp.writelines(proxy + ',' + proxy_anonymous + ',' + proxy_type + '\n')


def run():
    img_list = get_all_png()
    img_len = len(img_list)
    for index, img in enumerate(img_list, 1):
        print '[+] [%s/%s] now img is: %s' % (index, img_len, img)
        ocr(img)
    print 'all success'


if __name__:
    print 'start...'
    run()
    print 'all done'
