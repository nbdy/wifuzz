from runnable import Runnable


class Scanner(Runnable):
    iface = None
    found = []

    def __init__(self, iface=None):
        Runnable.__init__(self)
        self.iface = iface

    def callback(self, pdu):
        raise NotImplementedError

    def run(self):
        raise NotImplementedError
