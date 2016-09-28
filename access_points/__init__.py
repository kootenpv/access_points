import sys
import re
import platform
import subprocess
import plistlib


def rssi_to_quality(rssi):
    return 2 * (rssi + 100)


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


class OSXWifiScanner(WifiScanner):

    def get_cmd(self):
        path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/"
        cmd = "airport -s -x"
        return path + cmd

    def parse_output(self, output):
        if sys.version_info >= (3, 4):
            read_plist = plistlib.loads
        elif sys.version_info >= (3, 1): #Why would you break a stdlib API *twice*?
            read_plist = plistlib.readPlistFromBytes
        else:
            read_plist = plistlib.readPlistFromString

        results = []
        for network in read_plist(output):
            ssid = network['SSID_STR']
            bssid = network['BSSID']
            rssi = int(network['RSSI'])
            supported_security = []
            if 'WPA_IE' in network.keys():
                supported_security.append("WPA")
            if 'RSN_IE' in network.keys():
                supported_security.append("WPA2")
            security = ', '.join(supported_security)
            ap = AccessPoint(ssid, bssid, rssi_to_quality(rssi), security)
            results.append(ap)
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


class LinuxWifiScanner(WifiScanner):

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
        try:
            output = output.decode("utf8")
        except:
            pass
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
            elif num > bssid_line + 2 and re.search("\d/\d", line):
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
        return LinuxWifiScanner()
    elif operating_system == 'Windows':
        return WindowsWifiScanner()


def main():
    import json
    wifi_scanner = get_scanner()
    access_points = wifi_scanner.get_access_points()
    if '-n' in sys.argv:
        print(len(access_points))
    else:
        print(json.dumps(access_points))
