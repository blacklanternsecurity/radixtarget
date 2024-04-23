# RadixTarget

[![Python Version](https://img.shields.io/badge/python-3.9+-blue)](https://www.python.org) [![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://github.com/blacklanternsecurity/radixtarget/blob/master/LICENSE) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![tests](https://github.com/blacklanternsecurity/radixtarget/actions/workflows/tests.yml/badge.svg)](https://github.com/blacklanternsecurity/radixtarget/actions/workflows/tests.yml) [![Codecov](https://codecov.io/gh/blacklanternsecurity/radixtarget/graph/badge.svg?token=7IPWMYMTGZ)](https://codecov.io/gh/blacklanternsecurity/radixtarget)

RadixTarget is a performant radix implementation designed for quick lookups of IP addresses/networks and DNS hostnames. Written in pure python and capable of roughly 100,000 lookups per second regardless of the size of the database.

Used by:
- [BBOT (Bighuge BLS OSINT Tool)](https://github.com/blacklanternsecurity/bbot)
- [cloudcheck](https://github.com/blacklanternsecurity/cloudcheck)

### Installation ([PyPi](https://pypi.org/project/radixtarget/))

```bash
pip install radixtarget
```

### Example Usage

```python
from radixtarget import RadixTarget

rt = RadixTarget()

# IPv4
rt.insert("192.168.1.0/24")
rt.search("192.168.1.10") # IPv4Network("192.168.1.0/24")
rt.search("192.168.2.10") # None

# ipv6
rt.insert("dead::/64")
rt.search("dead::beef") # IPv6Network("dead::/64")
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

# Custom data nodes
rt.insert("evilcorp.co.uk", "custom_data")
rt.search("www.evilcorp.co.uk") # "custom_data"
```