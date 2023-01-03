import os
from access_points import OSXWifiScanner, TermuxWifiScanner
from access_points import WindowsWifiScanner
from access_points import IwlistWifiScanner
from access_points import NetworkManagerWifiScanner
from access_points import get_scanner
from access_points import AccessPoint
from access_points import rssi_to_quality

try:
    basestring
except NameError:
    basestring = str


def get_data_path():
    if os.path.isdir("../data"):
        return "../data"
    else:
        return "data"


def read_output(fn):
    data_dir = get_data_path()
    with open(os.path.join(data_dir, fn)) as f:
        return f.read()


def assert_access_point(aps, bssid_required=True):
    assert isinstance(aps, list)
    for ap in aps:
        assert isinstance(ap['quality'], int)
        assert isinstance(ap['ssid'], basestring) and ap['ssid'] != ''
        # `ap['bssid']` can sometimes be empty, e.g. on macOS Monterey
        if bssid_required:
            assert isinstance(ap['bssid'], basestring) and ap['bssid'] != ''


def parse_output(wifi_scanner, fname, bssid_required=True):
    output = read_output(fname)
    aps = wifi_scanner.parse_output(output)
    assert_access_point(aps, bssid_required)
    return aps


def assert_all_included(aps, answers):
    """
    Take in list of answers, assert they are all in aps
    """
    assert len(aps) == len(answers)
    for a in answers:
        assert AccessPoint(*a) in aps


def test_scan():
    scanner = get_scanner()
    aps = scanner.get_access_points()
    # We don't know if we necessarily get BSSIDs from a live scan;
    # best to err on the side of caution here and not require a match.
    assert_access_point(aps, False)


def test_iwlist():
    aps = parse_output(IwlistWifiScanner(), "iwlist_test.txt")
    assert len(aps) == 9

    iwlist_ans = [
        ('Thomson19D0C8',
         '00:00:00:00:00:00',
         57,
         [u'IEEE 802.11i/WPA2 Version 1', u'WPA Version 1']),
        ('H368NDF1690',
         '00:00:00:00:00:00',
         42,
         [u'IEEE 802.11i/WPA2 Version 1',
          u'WPA Version 1']),
        ('KPN Fon',
         '00:00:00:00:00:00',
         34,
         []),
        ('De Hypotheker',
         '00:00:00:00:00:00',
         22,
         [u'IEEE 802.11i/WPA2 Version 1']),
        ('KalkZeist',
         '00:00:00:00:00:00',
         42,
         [u'WPA Version 1']),
        ('Bon Soigne',
         '00:00:00:00:00:00',
         33,
         [u'WPA Version 1',
          u'IEEE 802.11i/WPA2 Version 1']),
        ('Sitecom1E447C',
         '00:00:00:00:00:00',
         29,
         [u'IEEE 802.11i/WPA2 Version 1']),
        ('Ziggo',
         '00:00:00:00:00:00',
         31,
         [u'IEEE 802.11i/WPA2 Version 1']),
        ('Free Wi-Fi Zeist ',
         '00:00:00:00:00:00',
         30,
         [])
    ]
    assert_all_included(aps, iwlist_ans)


def test_nmcli():
    aps = parse_output(NetworkManagerWifiScanner(), "nmcli_test.txt")
    assert len(aps) == 9

    nmcli_ans = [
        ('XXXXXXXXX', '00:00:XX:00:0X:X0', 0, 'WPA1'),
        ('XXXXXX00D0X0', 'X0:00:XX:00:X0:X0', 0, 'WPA1 WPA2'),
        ('X000XXX0000', '00:00:X0:XX:00:00', 0, 'WPA1 WPA2'),
        ('XXX XXX', '0X:00:X0:XX:00:00', 0, ''),
        ('XXX-XXX0000000000', '0X:00:X0:00:00:00', 0, 'WPA1 WPA2'),
        ('XXXX XX-XX XXXXX ', '0X:XX:X0:00:X0:00', 0, ''),
        ('XXXXX', '0X:XX:X0:00:X0:00', 0, 'WPA2 802.1X'),
        ('XX XXXXXXXXXX', '00:00:XX:00:00:X0', 0, 'WPA2'),
        ('XXX000000X000', '0X:X0:0X:00:X0:00', 0, 'WPA1 WPA2'),
    ]
    assert_all_included(aps, nmcli_ans)


def test_windows():
    aps = parse_output(WindowsWifiScanner(), "windows_test.txt")
    assert len(aps) == 37

    win_ans = [
        ('iConnect', '00:25:45:35:06:cd', 63, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c8:0c:7d', 20, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c8:07:8d', 15, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c3:7e:1d', 45, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c8:8f:3d', 46, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c3:7f:9d', 13, 'WPA2-Enterprise'),
        ('iConnect', '00:25:45:35:06:c2', 86, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c3:06:02', 26, 'WPA2-Enterprise'),
        ('iConnect', '00:25:45:a4:e5:72', 61, 'WPA2-Enterprise'),
        ('iConnect', '00:25:45:a5:06:92', 41, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c8:9a:1d', 36, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c3:7d:32', 50, 'WPA2-Enterprise'),
        ('iConnect', '00:25:45:a5:34:0d', 45, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c3:7e:12', 78, 'WPA2-Enterprise'),
        ('iConnect', '00:25:45:a4:e5:7d', 18, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c3:7e:82', 38, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c3:7f:b2', 51, 'WPA2-Enterprise'),
        ('iConnect', '00:25:45:a4:c7:cd', 36, 'WPA2-Enterprise'),
        ('iConnect', '30:37:a6:c3:76:6d', 30, 'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '00:25:45:a4:c7:cf',
         36,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c3:10:ff',
         15,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c3:7e:1f',
         45,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '00:25:45:35:06:cf',
         80,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c8:16:9f',
         20,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c8:8f:3f',
         46,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c3:7f:bf',
         18,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '00:25:45:a4:e5:df',
         35,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c3:7f:9f',
         13,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c3:7d:3f',
         31,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c3:76:6f',
         30,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '00:25:45:a5:34:0f',
         45,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c3:0b:bf',
         23,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c3:7e:8f',
         23,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '00:25:45:a4:e5:7f',
         16,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c8:07:8f',
         16,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c8:0c:7f',
         18,
         'WPA2-Enterprise'),
        ('R@06DO74VK71KM72JG64TW68!',
         '30:37:a6:c3:09:ff',
         26,
         'WPA2-Enterprise')
    ]
    assert_all_included(aps, win_ans)


def test_osx():
    aps = parse_output(OSXWifiScanner(), "osx_test.txt")
    assert len(aps) == 5

    osx_ans = [
        ('X000X000X00',
         '00:X0:00:00:0X:00',
         rssi_to_quality(-83),
         'WPA(PSK/AES,TKIP/TKIP) WPA2(PSK/AES,TKIP/TKIP)'),
        ('XXX-XXX0000000000',
         '0X:00:X0:00:00:00',
         rssi_to_quality(-68),
         'WPA(PSK/TKIP/TKIP) WPA2(PSK/AES/TKIP)'),
        ('XXXXXXXXX',
         '00:00:XX:00:0X:X0',
         rssi_to_quality(-52),
         'WPA(PSK/TKIP/TKIP)'),
        ('XX-XXX',
         '0X:00:XX:X0:0X:X0',
         rssi_to_quality(-75),
         'WPA(PSK/TKIP/TKIP) WPA2(PSK/AES/TKIP)'),
        ('XXXXXXX00X0X0',
         'X0:00:XX:00:X0:X0',
         rssi_to_quality(-58),
         'WPA(PSK/TKIP/TKIP) WPA2(PSK/AES/TKIP)')
    ]
    assert_all_included(aps, osx_ans)

def test_osx_monterey():
    # BSSID isn't a required match for macOS Monterey because it's not there.
    aps = parse_output(OSXWifiScanner(), "osx_monterey_test.txt", False)
    assert len(aps) == 5

    osx_monterey_ans = [
        ('X000X000X00',
         '',
         rssi_to_quality(-83),
         'WPA(PSK/AES,TKIP/TKIP) WPA2(PSK/AES,TKIP/TKIP)'),
        ('XXX-XXX0000000000',
         '',
         rssi_to_quality(-68),
         'WPA(PSK/TKIP/TKIP) WPA2(PSK/AES/TKIP)'),
        ('XXXXXXXXX',
         '',
         rssi_to_quality(-52),
         'WPA(PSK/TKIP/TKIP)'),
        ('XX-XXX',
         '',
         rssi_to_quality(-75),
         'WPA(PSK/TKIP/TKIP) WPA2(PSK/AES/TKIP)'),
        ('XXXXXXX00X0X0',
         '',
         rssi_to_quality(-58),
         'WPA(PSK/TKIP/TKIP) WPA2(PSK/AES/TKIP)')
    ]
    assert_all_included(aps, osx_monterey_ans)


def test_termux():
    aps = parse_output(TermuxWifiScanner(), "termux_test.txt")
    assert len(aps) == 2

    termux_ans = [
        ('ABC',
         'c8:52:61:a6:5e:62',
         rssi_to_quality(-37),
         ''),
        ('ABC-5G',
         'c8:52:61:a6:5e:63',
         rssi_to_quality(-44),
         '')
    ]
    assert_all_included(aps, termux_ans)

def test_cjk():
    aps = parse_output(OSXWifiScanner(), "osx_cjk_test.txt", False)
    assert len(aps) == 5

    osx_cjk_ans = [
        ('P880', '', rssi_to_quality(-87), 'RSN(PSK/AES/AES' ),
        ('HuaB5', '', rssi_to_quality(-83), 'RSN(PSK/AES/AES' ),
        ('小米共享WiFi_B496', '', rssi_to_quality(-76), 'RSN(PSK/AES/AES' ),
        ('不要亂改網路名稱', '', rssi_to_quality(-71), 'RSN(PSK/AES/AES' ),
        ('HuaB5', '', rssi_to_quality(-70), 'RSN(PSK/AES/AES' ),
    ]
    assert_all_included(aps, osx_cjk_ans)