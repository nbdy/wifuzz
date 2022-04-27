from time import sleep
from runnable import Runnable


class ADBFuzzer(Runnable):
    adb_devices = None
    fuzzers = []
    do_run = False

    def __init__(self, adb_devices, fuzzers):
        Runnable.__init__(self)
        self.adb_devices = adb_devices
        self.fuzzers = fuzzers
        self.do_run = True

    def run(self) -> None:
        for f in self.fuzzers:
            f.start()
        while self.do_run:
            for ad in self.adb_devices.devices:
                ad.start_logcat()
                ad.crashes.show()
            sleep(1)

    def stop(self):
        self.do_run = False
        for ad in self.adb_devices.devices:
            ad.stop_logcat()
