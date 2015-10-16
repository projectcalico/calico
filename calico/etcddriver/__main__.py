import socket
from threading import Thread
import time
from calico.etcddriver.driver import report_status, resync_and_merge
import logging

_log = logging.getLogger(__name__)


def main():
    t = Thread(target=report_status)
    t.daemon = True
    t.start()

    update_socket = socket.socket(socket.AF_UNIX,
                                  socket.SOCK_SEQPACKET)
    while True:
        try:
            update_socket.connect("/tmp/felix.sck")
        except:
            _log.exception("Failed to connect to felix...")
            time.sleep(1)
        else:
            break

    resync_and_merge(update_socket)


if __name__ == "__main__":
    main()
