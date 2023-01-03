__project__ = "access_points"
__version__ = "0.4.72"
__repo__ = "https://github.com/kootenpv/access_points"

import sys
import re
import platform
import subprocess
import json

def count_cjk_characters(string):
    # Use the regex to find all CJK characters in the string
    cjk_characters = re.findall(r'[\u4e00-\u9fff]', string)
    # Return the number of characters found
    return len(cjk_characters)

def ensure_str(output):
    try:
        output = output.decode("utf8",errors='ignore')
    except UnicodeDecodeError:
        output = output.decode("utf16",errors='ignore')
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

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, d):
        self.__dict__ = d

    def __repr__(self):
        args = ", ".join(["{}={}".format(k, v) for k, v in self.items()])
        return "AccessPoint({})".format(args)


class WifiScanner(object):

    def __init__(self, device=""):
        self.device = device
        self.cmd = self.get_cmd()

    def get_cmd(self):
        raise NotImplementedError

    def parse_output(self, output):
        raise NotImplementedError

    def get_access_points(self):
        out = self.call_subprocess(self.cmd)
        results = self.parse_output(ensure_str(out))
        return results

    @staticmethod
    def call_subprocess(cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (out, _) = proc.communicate()
        return out

class OSXWifiScanner(WifiScanner):

    def get_cmd(self):
        path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/"
        cmd = "airport -s"
        return path + cmd

    # OSX Monterey doesn't output the BSSID unless you `sudo` which means the
    # old method using a regexp to match those lines fails.  Since the output
    # is column-formatted, we can use that instead and it works on both
    # Monterey-without-BSSID and pre-Monterey-with-BSSID.
    def parse_output(self, output):
        results = []
        security_start_index = False
        # First line looks like this (multiple whitespace truncated to fit.)
        # `\w+SSID BSSID\w+  RSSI CHANNEL HT CC SECURITY (auth/unicast/group)`
        # `       ^ ssid_end_index`
        # `                  ^ rssi_start_index`
        # `        ^       ^ bssid`
        for line in output.split("\n"):
            if line.strip().startswith("SSID BSSID"):
                security_start_index = line.index("SECURITY")
                ssid_end_index = line.index("SSID") + 4
                rssi_start_index = line.index("RSSI")
            elif line and security_start_index and 'IBSS' not in line:
                try:
                    ssid = line[0:ssid_end_index].strip()
                    cjk_len = count_cjk_characters(ssid)
                    if cjk_len > 0:
                        line = line[0:ssid_end_index] + (cjk_len * 2 + 1) * ' ' + line[ssid_end_index+1:]

                    bssid = line[ssid_end_index+1:rssi_start_index-1].strip()
                    rssi = line[rssi_start_index:rssi_start_index+4].strip()
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
                if ssid == '':
                    # truely empty SSID
                    ssid = ' '
                ssid_line = num
            elif num == ssid_line + 2:
                security = ":".join(line.split(":")[1:]).strip()
            elif line.startswith("BSSID"):
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
        # note that this command requires some time in between / rescan
        return "nmcli -t -f ssid,bssid,signal,security device wifi list"

    def parse_output(self, output):
        results = []

        for line in output.strip().split('\n'):
            try:
                ssid, bssid, quality, security = split_escaped(line, ':')
            except ValueError:
                continue
            access_point = AccessPoint(ssid, bssid, int(quality), security)
            results.append(access_point)

        return results

    @classmethod
    def is_available(cls):
        """Whether NetworkManager is available on the system."""

        try:
            proc = subprocess.Popen(
                ['systemctl', 'status', 'NetworkManager'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc.communicate()
            return proc.returncode == 0
        except OSError:
            return False


class IwlistWifiScanner(WifiScanner):

    def get_cmd(self):
        return "sudo iwlist {} scanning 2>/dev/null".format(self.device)

    def parse_output(self, output):
        ssid = None
        bssid = None
        bssid_line = -1000000
        quality = None
        security = None
        security = []
        results = []
        for num, line in enumerate(output.split("\n")):
            line = line.strip()
            if line.startswith("Cell"):
                if bssid is not None:
                    ap = AccessPoint(ssid, bssid, quality, security)
                    results.append(ap)
                    security = []
                bssid = ":".join(line.split(":")[1:]).strip()
                bssid_line = num
            elif line.startswith("ESSID"):
                ssid = ":".join(line.split(":")[1:]).strip().strip('"')
            elif num > bssid_line + 2 and re.search(r"\d/\d", line):
                quality = int(line.split("=")[1].split("/")[0])
                bssid_line = -1000000000
            elif line.startswith("IE:") and line.find('Unknown') == -1:
                security.append(line[4:])
        if bssid is not None:
            ap = AccessPoint(ssid, bssid, quality, security)
            results.append(ap)
        return results


class TermuxWifiScanner(WifiScanner):
    """Wifi scanning tool using Termux on Android"""
    def get_cmd(self):
        return 'termux-wifi-scaninfo'

    def parse_output(self, output):
        data = json.loads(output)
        if not isinstance(data, list):
            return []  # Happens when permission not granted
        return [
            AccessPoint(i['ssid'], i['bssid'], rssi_to_quality(i['rssi']), '')
            for i in data
        ]

    @staticmethod
    def is_available():
        cmd_code = subprocess.call(
            ['which', 'termux-wifi-scaninfo'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return cmd_code == 0


def get_scanner(device=""):
    operating_system = platform.system()
    if operating_system == 'Darwin':
        return OSXWifiScanner(device)
    elif operating_system == 'Linux':
        if NetworkManagerWifiScanner.is_available():
            return NetworkManagerWifiScanner(device)
        elif TermuxWifiScanner.is_available():
            return TermuxWifiScanner(device)
        else:
            return IwlistWifiScanner(device)
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
        device = [x for x in sys.argv[1:] if "-" not in x] or [""]
        device = device[0]
        wifi_scanner = get_scanner(device)
        access_points = wifi_scanner.get_access_points()
        if '-n' in sys.argv:
            print(len(access_points))
        else:
            print(json.dumps(access_points))


if __name__ == '__main__':
    main()
