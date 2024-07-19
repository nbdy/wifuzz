from os import geteuid
from sys import argv
from terminaltables import AsciiTable

from wifuzz.Config import Configuration
from wifuzz.ADBFuzzer import ADBFuzzer
from wifuzz.Utils import start_thread_kbi, create_mac_table, validate_mac
from wifuzz.BT import BluetoothFuzzer
from wifuzz.WiFi import WiFiFuzzer, set_monitor_mode


def choose_targets():
    r = []
    print("enter macs you want to target")
    print("ctrl + c to start fuzzing")
    try:
        while True:
            i = input("> ")
            if not validate_mac(i):
                print(i, "is not a mac address")
            else:
                r.append(i)
    except KeyboardInterrupt:
        print()
        return r


class Manager:
    def __init__(self, configuration: Configuration):
        self.configuration = configuration

    def scan(self):
        if self.configuration.bt:
            from wifuzz.BT import BluetoothScanner
            if not self.configuration.iface_bt:
                print("no bluetooth interface found")
                exit()
            bts = BluetoothScanner(self.configuration.iface_bt)
            print("scanning for bluetooth macs")
            start_thread_kbi(bts)
            print(AsciiTable(create_mac_table("bluetooth", bts.found, self.configuration.mac_lookup)).table)
        if self.configuration.wifi:
            from wifuzz.WiFi import WiFiScanner
            if not self.configuration.iface_wl:
                print("no wifi interface found")
                exit()
            wts = WiFiScanner(self.configuration.iface_wl)
            print("scanning for wifi macs")
            start_thread_kbi(wts)
            print(AsciiTable(create_mac_table("wifi", wts.found, self.configuration.mac_lookup)).table)

        self.configuration.targets = choose_targets()

    def fuzz(self):
        if self.configuration.adb:
            adb_fuzzer = ADBFuzzer(self.configuration.adb_devices, [])
            if self.configuration.wifi:
                print("creating wifi fuzzer with interface", self.configuration.iface_wl)
                fuzzer = WiFiFuzzer(self.configuration.iface_wl)
                fuzzer.targets = self.configuration.targets_wifi
                adb_fuzzer.fuzzers.append(fuzzer)
            if self.configuration.bt:
                print("creating bluetooth fuzzer with interface", self.configuration.iface_bt)
                fuzzer = BluetoothFuzzer(self.configuration.iface_bt)
                fuzzer.targets.append(self.configuration.targets_bt)
                adb_fuzzer.fuzzers.append(fuzzer)

            try:
                print("running")
                adb_fuzzer.start()
                adb_fuzzer.join()
            except KeyboardInterrupt:
                print("stopping..")
                adb_fuzzer.stop()
                print("stopped")
        else:
            print("only adb error collection is implemented yet")
            pass  # todo server/client stuff to monitor processes on other machines


def main():
    if geteuid() != 0:
        print("i need privileges")
        exit()

    configuration = Configuration.parse(argv)

    if configuration.mac_lookup:
        create_mac_table("mac_lookup", ["ff:ff:ff:ff:ff:ff"])

    if configuration.wifi:
        configuration.iface_wl = set_monitor_mode(configuration.iface_wl)

    manager = Manager(configuration)

    if configuration.scan:
        manager.scan()

    manager.fuzz()

    if configuration.wifi:
        configuration.iface_wl = set_monitor_mode(configuration.iface_wl, False)

    print("done")


if __name__ == '__main__':
    main()
