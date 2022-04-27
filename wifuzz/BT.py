from wifuzz.Fuzzer import Fuzzer
from wifuzz.Scanner import Scanner

from scapy.layers.bluetooth import *
from progressbar import ProgressBar
from subprocess import check_output
from btpy import ClassicDevice


def get_interface():
    o = check_output(["hciconfig"])
    i = o.split(b":")[0]
    return int(i[-1])


class BluetoothFuzzer(Fuzzer):
    name = "Bluetooth Fuzzer"
    sock = None
    targets = []
    frame_combos = [
        [None, HCI_Hdr, HCI_Command_Hdr]
    ]

    def run(self) -> None:
        self.sock = BluetoothHCISocket()
        self.f_send = self.sock.send
        for t in self.targets:
            self.fuzz(t)

    def stop(self):
        self.do_run = False
        self.sock.close()


class BluetoothScanner(Scanner):
    def __init__(self, iface=0):
        Scanner.__init__(self, iface)

    def callback(self, device):
        if device.address not in self.found:
            self.found.append(device.address)

    def run(self):
        b = ProgressBar()
        while self.do_run:
            for d in ClassicDevice.scan(3):
                self.callback(d)
            b.update(len(self.found))
