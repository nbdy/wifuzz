from mac_vendor_lookup import MacLookup
from loguru import logger as log
import re

REGEX_MAC = re.compile("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def start_thread_kbi(tc):
    try:
        tc.start()
    except KeyboardInterrupt:
        log.info("\nCaught CTRL + C")
        tc.stop()


def create_mac_table(key, lst, lookup=False):
    td = [[key]]
    m = None

    if lookup:
        td[0].append("vendor")
        m = MacLookup()

    for i in lst:
        try:
            if lookup:
                td.append([i, m.lookup(i)])
            else:
                td.append([i])
        except Exception as e:
            log.debug(e)
            td.append([i, ""])
    return td


def validate_mac(address):
    return REGEX_MAC.match(address)
