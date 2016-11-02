# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2016-11-02 18:52:07
# @Last Modified by:   lock
# @Last Modified time: 2016-11-02 18:55:30
from random import Random
def random_str(randomlength=8):
    str = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    length = len(chars) - 1
    random = Random()
    for i in range(randomlength):
        str+=chars[random.randint(0, length)]
    return str


def run():
	with open("./password.txt",'w') as fp:
		while True:
			str = random_str(6)
			fp.write(str+"\n")


if __name__ == '__main__':
	run()