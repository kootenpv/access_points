from access_points import OSXWifiScanner
from access_points import WindowsWifiScanner
from access_points import IwlistWifiScanner
from access_points import NetworkManagerWifiScanner
from access_points import get_scanner


def read_output(fn):
    with open(fn) as f:
        return f.read()


def assert_access_point(aps):
    assert isinstance(aps, list)
    for ap in aps:
        assert isinstance(ap['quality'], int)
        assert isinstance(ap['ssid'], str) and ap['ssid'] != ''
        assert isinstance(ap['bssid'], str) and ap['ssid'] != ''


def parse_output(wifi_scanner, fname):
    output = read_output(fname)
    aps = wifi_scanner.parse_output(output)
    assert_access_point(aps)


def test_scan():
    scanner = get_scanner()
    aps = scanner.get_access_points()
    assert_access_point(aps)


def test_iwlist():
    parse_output(IwlistWifiScanner(), "data/iwlist_test.txt")


def test_nmcli():
    parse_output(NetworkManagerWifiScanner(), "data/nmcli_test.txt")


def test_windows():
    parse_output(WindowsWifiScanner(), "data/windows_test.txt")


def test_osx():
    parse_output(OSXWifiScanner(), "data/osx_test.txt")
