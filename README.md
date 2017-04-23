## access_points

[![Build Status](https://travis-ci.org/kootenpv/access_points.svg?branch=master)](https://travis-ci.org/kootenpv/access_points)
[![PyPI](https://img.shields.io/pypi/v/access_points.svg?style=flat-square)](https://pypi.python.org/pypi/access_points/)
[![PyPI](https://img.shields.io/pypi/pyversions/access_points.svg?style=flat-square)](https://pypi.python.org/pypi/access_points/)

Scan your WiFi and get access point information and signal quality.

Works on multiple platforms: Windows/OSX/Linux.

### Installation

    pip install access_points

On linux systems you might want to install `nmcli` (recommended) or `iwlist`:

    apt-get install network-manager # Ubuntu
    pacman -S networkmanager        # Arch Linux


### Usage

In Python

```python
from access_points import get_scanner
wifi_scanner = get_scanner()
wifi_scanner.get_access_points()
# [{'bssid': 'XX:XX:XX:XX:XX:XX',
#   'quality': 90,
#   'security': 'WPA2(802.1x,Unrecognized(0)/AES/AES)',
#   'ssid': 'MyWifi1'},
#  {'bssid': 'XX:XX:XX:XX:XX:XX',
#   'quality': 80,
#   'security': 'WPA2(802.1x,Unrecognized(0),FT-802.1x/AES/AES)',
#   'ssid': 'NeighbourWifi1'}]
```

On command line:

```bash
access_points
# [{'bssid': 'XX:XX:XX:XX:XX:XX',
#   'quality': 90,
#   'security': 'WPA2(802.1x,Unrecognized(0)/AES/AES)',
#   'ssid': 'MyWifi1'},
#  {'bssid': 'XX:XX:XX:XX:XX:XX',
#   'quality': 130,
#   'security': 'WPA2(802.1x,Unrecognized(0),FT-802.1x/AES/AES)',
#   'ssid': 'NeighbourWifi1'}]
```

#### Using a different device:

Python:

    wifi_scanner = get_scanner("wlp2s0")

Command line:

    access_points wlp2s0

## Tests

This how to run tests:

    git clone https://github.com/kootenpv/access_points
    cd access_points
    python setup.py install
    tox
