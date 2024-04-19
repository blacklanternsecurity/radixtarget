# PyRadix

PyRadix is a performant radix implementation designed for looking up IP addresses, IP networks, and DNS hostnames. It is written in pure python.

Used by:
- https://github.com/blacklanternsecurity/bbot
- https://github.com/blacklanternsecurity/cloudcheck

### Example

```python
from pyradix import RadixTree

rt = RadixTree()

# IPv4
rt.insert("192.168.1.0/24")
rt.search("192.168.1.10") # ipaddress.ip_network("192.168.1.0/24")
rt.search("192.168.2.10") # None

# ipv6
rt.insert("dead::/64")
rt.search("dead::beef") # ipaddress.ip_network("dead::/64")
rt.search("dead:cafe::beef") # None

# DNS
rt.insert("net")
rt.insert("www.example.com")
rt.insert("test.www.example.com")

rt.search("net") # "net"
rt.search("evilcorp.net") # "net"
rt.search("www.example.com") # "www.example.com"
rt.search("asdf.test.www.example.com") # "test.www.example.com"
rt.search("example.com") # None
```