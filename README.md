## access_points

Scan your WiFi and get access point information and signal quality.

Works on multiple platforms: Windows/OSX/Linux.

### Installation

    pip install access_points

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

## Tests

This how to run tests:

    git clone https://github.com/kootenpv/access_points

My editor shows that I run the following command to run all tests:

    cd /Users/pascal/egoroot/access_points/ && py.test --pdb -x -s
