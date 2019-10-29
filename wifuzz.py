#!/usr/bin/python3

from os import geteuid
from sys import argv
from threading import Thread
from subprocess import Popen, PIPE
from scapy.layers.dot11 import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from scapy.all import fuzz, send


class Configuration(object):
    targets = []

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    @staticmethod
    def parse(args):
        i = 0
        _c = Configuration()
        while i < len(args):

            i += 1
        return _c


class Runnable(Thread):
    do_run = False
    daemon = True

    def __init__(self, **kwargs):
        Thread.__init__(self)
        self.__dict__.update(kwargs)
        self.do_run = True

    def stop(self):
        self.do_run = False


class ADB(Runnable):
    class Line(object):
        date = None
        time = None
        pid = None
        priority = None
        name = None
        text = None

        def __init__(self, line):
            self.text = line
            line = line.split()
            self.date = line[0]
            self.time = line[1]
            self.pid = line[2]
            self.priority = line[4]
            self.name = line[5]
            if self.name.endswith(b":"):
                self.name = self.name[0:-1]

    def run(self) -> None:
        adbp = Popen(["adb", "logcat"], stdout=PIPE, stderr=PIPE)
        while self.do_run:
            for l in adbp.stdout:
                if l.startswith(b"---"):
                    continue
                line = ADB.Line(l)
                if line.priority in [b'W', b'E']:
                    print(line.text)
                # if b'System.err:' in l.text:
                #     print(l.text)

# interesting names
# bt_sdp, bt_btif_sock_rfcomm, bt_btif, bt_vendor, bt_osi_thread
# BluetoothHealthServiceJni, BluetoothPanServiceJni, BluetoothHidServiceJni
# BluetoothSdpJni
# wificond, QCNEJ, WifiAPDataHandler
# WCNSS_FILTER
# ip


class Fuzzer(Runnable):
    targets = []
    frame_combos = []

    def fuzz(self, target):
        raise NotImplementedError

    def run(self) -> None:
        while self.do_run:
            for t in self.targets:
                self.fuzz(t)


class BluetoothFuzzer(Fuzzer):
    targets = []
    frame_combos = [
        [HCI_Hdr, HCI_Command_Hdr]
    ]

    sock = BluetoothHCISocket()

    def fuzz(self, target):
        p = None
        for fc in self.frame_combos:
            for f in fc:
                p /= fuzz(f())
        self.sock.send(p)

    def stop(self):
        self.do_run = False
        self.sock.close()


class WiFiFuzzer(Fuzzer):
    # iface = "wlp13s0"
    targets = ["dc:0b:34:c4:8c:06"]
    frame_combos = [
        [Dot11Beacon, Dot11Elt],
        [Dot11Beacon],
        [Dot11AssoReq, Dot11Elt, Dot11EltRates]
    ]

    def fuzz(self, target):
        p = Dot11(addr1=target)
        for fc in self.frame_combos:
            ff = p
            for f in fc:
                ff /= fuzz(f())
                print(ff.show())
                send(ff)


if __name__ == '__main__':
    if geteuid() != 0:
        print("i need privileges")
        exit()
    c = Configuration.parse(argv)
    adb = ADB()
    wf = WiFiFuzzer()
    try:
        wf.run()
        adb.run()
    except KeyboardInterrupt:
        adb.stop()
        wf.stop()
