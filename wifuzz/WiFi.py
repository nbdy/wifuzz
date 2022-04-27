from wifuzz.Fuzzer import Fuzzer
from wifuzz.Scanner import Scanner

from os import system
from time import sleep
from scapy.layers.dot11 import *
from scapy.all import AsyncSniffer
from netifaces import interfaces
from progressbar import ProgressBar


def get_interface():
    for i in interfaces():
        if i.startswith("wl"):
            return i
    return None


def set_monitor_mode(interface, enable=True):
    if interface is None:
        print("interface is none")
        return None
    if enable:
        print("enabling monitor mode on", interface)
        system("airmon-ng start %s >/dev/null 2>&1" % interface)
        return interface + "mon"
    else:
        print("disabling monitor mode on", interface)
        system("airmon-ng stop %s >/dev/null 2>&1" % interface)
        return interface[0:-3]


class WiFiFuzzer(Fuzzer):
    name = "WiFi Fuzzer"
    targets = []
    frame_combos = [
        [Dot11, Dot11Beacon, Dot11Elt],
        [Dot11, Dot11Beacon],
        [Dot11, Dot11AssoReq, Dot11Elt, Dot11EltRates]
    ]


class WiFiScanner(Scanner):
    daemon = False
    do_run = True

    @staticmethod
    def is_broadcast(addr):
        return addr == "ff:ff:ff:ff:ff:ff"

    def callback(self, pdu):
        mcs = [pdu.addr1, pdu.addr2, pdu.addr3, pdu.addr4]
        for m in mcs:
            if m is None or self.is_broadcast(m):
                continue
            if m not in self.found:
                self.found.append(m)

    def run(self):
        a = AsyncSniffer(iface=self.iface, prn=self.callback)
        a.start()
        c = ProgressBar()
        while self.do_run:
            c.update(len(self.found))
            sleep(1)  # be nice to the cpu
        a.stop()
