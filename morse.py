# -*- coding: utf-8 -*-
# @Author: lock
# @Date:   2017-12-15 15:39:07
# @Last Modified by:   lock
# @Last Modified time: 2017-12-15 16:13:19
# 摩斯密码是由美国的三缪摩斯发明的一套加密算法，是一种断断续续的信号代码。
import optparse


# 摩斯代码表
CODE_TABLE = {
    # 26 个英文字符
    'A': '.-',     'B': '-...',   'C': '-.-.',
    'D': '-..',    'E': '.',      'F': '..-.',
    'G': '--.',    'H': '....',   'I': '..',
    'J': '.---',   'K': '-.-',    'L': '.-..',
    'M': '--',     'N': '-.',     'O': '---',
    'P': '.--.',   'Q': '--.-',   'R': '.-.',
    'S': '...',    'T': '-',      'U': '..-',
    'V': '...-',   'W': '.--',    'X': '-..-',
    'Y': '-.--',   'Z': '--..',
            
    # 10 个数字
    '0': '-----',  '1': '.----',  '2': '..---',
    '3': '...--',  '4': '....-',  '5': '.....',
    '6': '-....',  '7': '--...',  '8': '---..',
    '9': '----.',
            
    # 16 个特殊字符
    ',': '--..--', '.': '.-.-.-', ':': '---...', ';': '-.-.-.',
    '?': '..--..', '=': '-...-',  "'": '.----.', '/': '-..-.',
    '!': '-.-.--', '-': '-....-', '_': '..--.-', '(': '-.--.',
    ')': '-.--.-', '$': '...-..-','&': '. . . .','@': '.--.-.'
 
    # 你还可以自定义
 
}
 
def encode(msg):
    msg = msg.strip()
    morse = ''
    for char in msg:
        if char == ' ':
            morse += ' '
        else:
            morse += CODE_TABLE[char.upper()] + ' '
    return morse
 
def decode(morse):
    morse = morse.strip()
    msg = ''
    codes = morse.split(' ')
 
    for code in codes:
        if code == '':
            msg += ' '
        else:
            UNCODE = dict(map(lambda t:(t[1], t[0]), CODE_TABLE.items()))
            msg += UNCODE[code]
    return msg.lower()
 
 
if __name__ == '__main__':
    parser = optparse.OptionParser('usage\t -e|-d msg or -h get help')
    parser.add_option('-e', dest='encode_message', type='string', help='encode message',)
    parser.add_option('-d', dest='decode_message', type='string', help='decode message',)
    options, args = parser.parse_args()
    encode_msg = options.encode_message
    decode_msg = options.decode_message
    if encode_msg!=None and decode_msg==None:
        #encode msg
        print encode(encode_msg)
    elif encode_msg == None and decode_msg!=None:
        #decode msg
        print decode(decode_msg)
    else:
        print(parser.usage)
        exit(0)


