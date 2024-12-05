# RadixTarget

[![Python Version](https://img.shields.io/badge/python-3.9+-blue)](https://www.python.org) [![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://github.com/blacklanternsecurity/radixtarget/blob/master/LICENSE) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![tests](https://github.com/blacklanternsecurity/radixtarget/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/blacklanternsecurity/radixtarget/actions/workflows/tests.yml) [![Codecov](https://codecov.io/gh/blacklanternsecurity/radixtarget/graph/badge.svg?token=7IPWMYMTGZ)](https://codecov.io/gh/blacklanternsecurity/radixtarget)

RadixTarget is a performant radix implementation designed for quick lookups of IP addresses/networks and DNS hostnames. 

RadixTarget is:
- Written in pure python
- Capable of ~100,000 lookups per second regardless of database size
- 100% test coverage
- Used by:
    - [BBOT](https://github.com/blacklanternsecurity/bbot)
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
rt.add("192.168.1.0/24")
rt.get("192.168.1.10") # IPv4Network("192.168.1.0/24")
rt.get("192.168.2.10") # None

# IPv6
rt.add("dead::/64")
rt.get("dead::beef") # IPv6Network("dead::/64")
rt.get("dead:cafe::beef") # None

# DNS
rt.add("net")
rt.add("www.example.com")
rt.add("test.www.example.com")
rt.get("net") # "net"
rt.get("evilcorp.net") # "net"
rt.get("www.example.com") # "www.example.com"
rt.get("asdf.test.www.example.com") # "test.www.example.com"
rt.get("example.com") # None

# Custom data nodes
rt.add("evilcorp.co.uk", "custom_data")
rt.get("www.evilcorp.co.uk") # "custom_data"
```