__project__ = "access_points"
__version__ = "0.2.39"
__repo__ = "https://github.com/kootenpv/access_points"

import sys
import re
import platform
import subprocess
import json


def ensure_str(output):
    try:
        output = output.decode("utf8")
    except AttributeError:
        pass
    return output


def rssi_to_quality(rssi):
    return 2 * (rssi + 100)


def split_escaped(string, separator):
    """Split a string on separator, ignoring ones escaped by backslashes."""

    result = []
    current = ''
    escaped = False
    for char in string:
        if not escaped:
            if char == '\\':
                escaped = True
                continue
            elif char == separator:
                result.append(current)
                current = ''
                continue
        escaped = False
        current += char
    result.append(current)
    return result


class AccessPoint(dict):

    def __init__(self, ssid, bssid, quality, security):
        dict.__init__(self, ssid=ssid, bssid=bssid, quality=quality, security=security)

    def __getattr__(self, attr):
        return self.get(attr)


class WifiScanner(object):

    def __init__(self):
        self.cmd = self.get_cmd()

    def get_cmd(self):
        raise NotImplementedError

    def parse_output(self, output):
        raise NotImplementedError

    def get_access_points(self):
        out = self.call_subprocess(self.cmd)
        results = self.parse_output(out)
        return results

    @staticmethod
    def call_subprocess(cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (out, _) = proc.communicate()
        return out

# Unexpected error
# import plistlib
# class OSXWifiScanner(WifiScanner):

#     def get_cmd(self):
#         path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/"
#         cmd = "airport -s -x"
#         return path + cmd

#     def parse_output(self, output):
#         if sys.version_info >= (3, 4):
#             read_plist = plistlib.loads
#         elif sys.version_info >= (3, 1):  # Why would you break a stdlib API *twice*?
#             read_plist = plistlib.readPlistFromBytes
#         else:
#             read_plist = plistlib.readPlistFromString
#         results = []
#         for network in read_plist(output):
#             try:
#                 ssid = network['SSID_STR']
#                 bssid = network['BSSID']
#                 rssi = int(network['RSSI'])
#                 supported_security = []
#                 if 'WPA_IE' in network.keys():
#                     supported_security.append("WPA")
#                 if 'RSN_IE' in network.keys():
#                     supported_security.append("WPA2")
#                 security = ', '.join(supported_security)
#                 ap = AccessPoint(ssid, bssid, rssi_to_quality(rssi), security)
#                 results.append(ap)
#             except Exception as e:
#                 import pdb
#                 pdb.set_trace()

#         return results


class OSXWifiScanner(WifiScanner):

    def get_cmd(self):
        path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/"
        cmd = "airport -s"
        return path + cmd

    def parse_output(self, output):
        results = []
        line_parser = []
        output = ensure_str(output)
        # 5 times 2 "letters and/or digits" followed by ":"
        # Then one time only 2 "letters and/or digits"
        # Use non-capturing groups (?:...) to use {} for amount
        # One wrapping group (...) to capture the whole thing
        bbsid_re = re.compile("((?:[0-9a-zA-Z]{2}:){5}(?:[0-9a-zA-Z]){2})")
        for line in output.split("\n"):
            if line.strip().startswith("SSID BSSID"):
                security_start_index = line.index("SECURITY")
            elif line and security_start_index and 'IBSS' not in line:
                try:
                    ssid = bbsid_re.split(line)[0].strip()
                    bssid = bbsid_re.findall(line)[0]
                    rssi = bbsid_re.split(line)[-1].strip().split()[0]
                    security = line[security_start_index:]
                    ap = AccessPoint(ssid, bssid, rssi_to_quality(int(rssi)), security)
                    results.append(ap)
                except Exception as e:
                    msg = "Please provide the output of the error below this line at {}"
                    print(msg.format("github.com/kootenpv/access_points/issues"))
                    print(e)
                    print("Line:")
                    print(line)
                    print("Output:")
                    print(output)
        return results


class WindowsWifiScanner(WifiScanner):

    def get_cmd(self):
        return "netsh wlan show networks mode=bssid"

    def parse_output(self, output):
        ssid = None
        ssid_line = -100
        bssid = None
        bssid_line = -100
        quality = None
        security = None
        results = []
        for num, line in enumerate(output.split("\n")):
            line = line.strip()
            if line.startswith("SSID"):
                ssid = " ".join(line.split()[3:]).strip()
                ssid_line = num
            elif num == ssid_line + 2:
                security = ":".join(line.split(":")[1:]).strip()
            elif line.startswith("BSSID"):
                if bssid is not None:
                    ap = AccessPoint(ssid, bssid, quality, security)
                    results.append(ap)
                bssid = ":".join(line.split(":")[1:]).strip()
                bssid_line = num
            elif num == bssid_line + 1:
                quality = int(":".join(line.split(":")[1:]).strip().replace("%", ""))
        if bssid is not None:
            ap = AccessPoint(ssid, bssid, quality, security)
            results.append(ap)
        return results


class NetworkManagerWifiScanner(WifiScanner):
    """Get access points and signal strengths from NetworkManager."""

    def get_cmd(self):
        return 'nmcli -t -f ssid,bssid,signal,security device wifi list'

    def parse_output(self, output):
        try:
            output = output.decode('utf8')
        except AttributeError:
            pass

        results = []

        for line in output.strip().split('\n'):
            ssid, bssid, quality, security = split_escaped(line, ':')
            access_point = AccessPoint(ssid, bssid, int(quality), security)
            results.append(access_point)

        return results

    @classmethod
    def is_available(cls):
        """Whether NetworkManager is available on the system."""

        try:
            proc = subprocess.Popen(
                ['which', 'nmcli'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc.communicate()
            return proc.returncode == 0
        except OSError:
            return False


class IwlistWifiScanner(WifiScanner):

    def get_cmd(self):
        return "sudo iwlist scan 2>/dev/null"

    def parse_output(self, output):
        ssid = None
        bssid = None
        bssid_line = -1000000
        quality = None
        security = None
        security = []
        results = []
        output = ensure_str(output)
        for num, line in enumerate(output.split("\n")):
            line = line.strip()
            if line.startswith("Cell"):
                bssid = ":".join(line.split(":")[1:]).strip()
                bssid_line = num
            elif line.startswith("ESSID"):
                if ssid is not None:
                    ap = AccessPoint(ssid, bssid, quality, security)
                    results.append(ap)
                    security = []
                ssid = ":".join(line.split(":")[1:]).strip().strip('"')
            elif num > bssid_line + 2 and re.search(r"\d/\d", line):
                quality = int(line.split("=")[1].split("/")[0])
                bssid_line = -1000000000
            elif line.startswith("IE:"):
                security.append(line[4:])
        if bssid is not None:
            ap = AccessPoint(ssid, bssid, quality, security)
            results.append(ap)
        return results


def get_scanner():
    operating_system = platform.system()
    if operating_system == 'Darwin':
        return OSXWifiScanner()
    elif operating_system == 'Linux':
        if NetworkManagerWifiScanner.is_available():
            return NetworkManagerWifiScanner()
        else:
            return IwlistWifiScanner()
    elif operating_system == 'Windows':
        return WindowsWifiScanner()


def print_version():
    sv = sys.version_info
    py_version = "{}.{}.{}".format(sv.major, sv.minor, sv.micro)
    print("access_points version: [{}], Python {}".format(__version__, py_version))
    version_parts = __version__.split(".")
    print("major version: {}  (breaking changes)".format(version_parts[0]))
    print("minor version: {}  (extra feature)".format(version_parts[1]))
    print("micro version: {} (commit count)".format(version_parts[2]))
    print("Find out the most recent version at {}".format(__repo__))


def main():
    if '-v' in sys.argv or 'version' in sys.argv:
        print_version()
    else:
        wifi_scanner = get_scanner()
        access_points = wifi_scanner.get_access_points()
        if '-n' in sys.argv:
            print(len(access_points))
        else:
            print(json.dumps(access_points))


if __name__ == '__main__':
    main()
