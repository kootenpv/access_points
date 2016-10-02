import os
from access_points import OSXWifiScanner
from access_points import WindowsWifiScanner
from access_points import IwlistWifiScanner
from access_points import NetworkManagerWifiScanner
from access_points import get_scanner

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


def assert_access_point(aps):
    assert isinstance(aps, list)
    for ap in aps:
        assert isinstance(ap['quality'], int)
        assert isinstance(ap['ssid'], basestring) and ap['ssid'] != ''
        assert isinstance(ap['bssid'], basestring) and ap['ssid'] != ''


def parse_output(wifi_scanner, fname):
    output = read_output(fname)
    aps = wifi_scanner.parse_output(output)
    assert_access_point(aps)
    return aps


def test_scan():
    scanner = get_scanner()
    aps = scanner.get_access_points()
    assert_access_point(aps)


def test_iwlist():
    aps = parse_output(IwlistWifiScanner(), "iwlist_test.txt")
    assert len(aps) == 9


def test_nmcli():
    aps = parse_output(NetworkManagerWifiScanner(), "nmcli_test.txt")
    assert len(aps) == 9


def test_windows():
    aps = parse_output(WindowsWifiScanner(), "windows_test.txt")
    assert len(aps) == 37


def test_osx():
    aps = parse_output(OSXWifiScanner(), "osx_test.txt")
    assert len(aps) == 5
