from wifuzz.WiFi import get_interface as get_wifi_interface
from wifuzz.BT import get_interface as get_bt_interface
from wifuzz.ADB import Devices


class Configuration(object):
    wifi = False
    bt = False
    scan = False
    mac_lookup = False

    adb = False
    adb_devices = None

    iface_bt = None
    iface_wl = None

    targets_bt = []
    targets_wifi = []

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.adb_devices = Devices()

    @staticmethod
    def help():
        print("usage: ./wifuzz.py {arguments}")
        print("\t{arguments}\t\t{example/hint}")
        print("\t-h\t--help\t\tthis")
        print("\t-a\t--adb\t\tuse adb")
        print("\t-d\t--device\tadb transport id")
        print("\t\t--devices\ttid1,tid2,tid5")
        print("\t-w\t--wifi\t\tuse wifi")
        print("\t-b\t--bt\t\tuse bluetooth")
        print("\t-t\t--target\tfe:ed:de:ad:be:ef")
        print("\t\t--targets\tde:ad:be:ef:b0:ff,c0:33:b3:ff:ee:33")
        print("\t-i\t--interface\tcall supply after -w/-b")
        print("\t-s\t--scan\t\tscan for mac addresses/targets")
        print("\t-m\t--mac-lookup\tlookup mac vendors")
        print("examples:")
        print("sudo ./wifuzz.py -a -w -b")
        print("\tonly one android device, finds target macs automatically, fuzzes wifi and bt")
        print("sudo ./wifuzz.py -a -w -t ff:ee:ee:dd:be:ef")
        print("\tonly one android device, targets specified mac, fuzzes wifi")
        print("sudo ./wifuzz.py -m -s -w -b -a")
        print("\tscans wifi and bt for macs, gets vendors for macs, only one android device, fuzzes wifi and bt")
        print("sudo ./wifuzz.py -w --targets fe:ee:ed:de:ea:ad,be:ee:ef:66:66:66 -w -i wlan0 -b -i hci0 -b \\\n"
              "                 42:00:66:66:66:66 -a -d 7ee96662")
        print("\tfuzzes specified target macs, with specified bt and wifi interfaces, hooks specified android dev id")
        exit()

    @staticmethod
    def filter_duplicates(lst):
        _t = []
        for i in lst:
            if i not in _t:
                _t.append(i)
        return _t

    def check(self):
        if not self.wifi and not self.bt:
            self.help()
        if self.adb and self.adb_devices.size() == 0:
            self.adb_devices.get()
            self.adb_devices.get_macs()
            for d in self.adb_devices.devices:
                print(d.__dict__)
                self.targets_wifi.append(d.mac_wifi)
                self.targets_bt.append(d.mac_bt)
        if (len(self.targets_wifi) + len(self.targets_bt)) == 0 and not self.scan:
            self.help()
        self.targets_wifi = self.filter_duplicates(self.targets_wifi)
        self.targets_bt = self.filter_duplicates(self.targets_bt)
        if self.wifi:
            if self.iface_wl is None:
                self.iface_wl = get_wifi_interface()
        if self.bt:
            if self.iface_bt is None:
                self.iface_bt = get_bt_interface()

    @staticmethod
    def parse(args):
        i = 0
        _c = Configuration()
        while i < len(args):
            a = args[i]
            if a in ["-t", "--target"]:
                if args[i - 1] in ["-b", "--bt"]:
                    _c.targets_bt.append(args[i + 1])
                elif args[i - 1] in ["-w", "--wifi"]:
                    _c.targets_wifi.append(args[i + 1])
            elif a in ["--targets"]:
                if args[i - 1] in ["-b", "--bt"]:
                    _c.targets_bt += args[i + 1].split(",")
                elif args[i - 1] in ["-w", "--wifi"]:
                    _c.targets_wifi += args[i + 1].split(",")
            elif a in ["-s", "--scan"]:
                _c.scan = True
            elif a in ["-w", "--wifi"]:
                _c.wifi = True
            elif a in ["-b", "--bt"]:
                _c.bt = True
            elif a in ["-a", "--adb"]:
                _c.adb = True
            elif a in ["-d", "--device"]:
                _c.adb_devices.add_by_id(args[i + 1])
            elif a in ["--devices"]:
                _c.adb_devices.add_by_ids(args[i + 1].split(","))
            elif a in ["-i", "--interface"]:
                if args[i - 1] in ["-b", "--bt"]:
                    _c.iface_bt = args[i + 1]
                elif args[i - 1] in ["-w", "--wifi"]:
                    _c.iface_wl = args[i + 1]
            elif a in ["-m", "--mac-lookup"]:
                _c.mac_lookup = True
            elif a in ["-h", "--help"]:
                Configuration.help()
            i += 1
        _c.check()
        return _c


if __name__ == '__main__':
    Configuration.help()
