from runnable import Runnable
from loguru import logger as log
from scapy.all import fuzz, send


class Fuzzer(Runnable):
    targets = []
    '''
    frame_combos = [
        [BasePacket, FuzzPacket, FuzzPacket],
        ...
    ]
    '''
    frame_combos = []
    f_send = send
    iface = None

    def __init__(self, iface=None):
        Runnable.__init__(self)
        self.iface = iface

    def fuzz(self, target):
        for fc in self.frame_combos:
            p = fc[0]  # base packet
            if p is not None:
                p = p(addr1=target)  # dot11 packet
            for fp in fc[1:]:
                p /= fuzz(fp())
            print(p.show())
            self.f_send(p)

    def run(self):
        for t in self.targets:
            if t is None:
                continue
            log.info("Fuzzing: {}", t)
            self.fuzz(t)
