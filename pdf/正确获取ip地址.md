事情不大，不是很重要的事情，只是获取下ip​ 。。。



##### 获取自身ip地址是很常见的事情

> 一部分人喜欢通过gethostbyname方式
>
> 也有一部分人喜欢从驱动信息中来获取



#####比如网上有人给出的一些答案类似：

```python
import socket
# 获取本机电脑名
myname = socket.getfqdn(socket.gethostname())
# 获取本机ip
myaddr = socket.gethostbyname(myname)
print myname
print myaddr
```

> 如果了解安全的同学，假如入参到gethostbyname中是一个由外部传入的域名参数，这种gethostname用的不好还可能还会出现ssrf攻击 (Use DNS Rebinding to Bypass SSRF)

##### 利用驱动信息

```python
import socket
import fcntl
import struct

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

print "eth0 = "+ get_ip_address('eth0')
```

>利用驱动信息去获取本机ip，这种方式需要知道**本机网卡的配置名称**，在有多块网卡的时候，这种直接指定eth0的形式还不能work，所以怎么看也不是很优雅



##### 利用UDP头部信息优雅获取

> 比如在python中

```python
import socket

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip
```

> 比如在golang中

```go
package main

import (
    "net"
    "fmt"
    "strings"
)

func main() {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        fmt.Println(err.Error())
        return
    }
    defer conn.Close()
    fmt.Println(strings.Split(conn.LocalAddr().String(), ":")[0])
}
```

> 这种方式有一个好处，通过生成一个udp请求包，ip会放到udp协议头中，然后从udp请求包中获取自身当前正在使用的网络ip，不用依赖于任何信息，也不用真正的发起udp请求。
>
> 如果你通过tcpdump或者wireshark去捕获底层数据包，你会发现不会捕获到任何请求。这种方式会向os申请udp端口，有一点点耗时，实际场景完全可以将获取到的ip缓存起来不用每次都查，相对于gethostbyname或者遍历网卡驱动信息的形式会好很多。