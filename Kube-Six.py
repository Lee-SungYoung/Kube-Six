#!/usr/bin/env python
from __future__ import print_function

import logging
import threading

try:
    raw_input          # Python 2
except NameError:
    raw_input = input  # Python 3

loglevel = "INFO" # DEBUG, INFO, WARN, NONE
logging.basicConfig(level=loglevel, format='%(message)s', datefmt='%H:%M:%S')

from src.modules.report.plain import PlainReporter

reporter = PlainReporter()

from src.core.events import handler
from src.core.events.common import HuntFinished, HuntStarted
from src.modules.discovery.hosts import HostScanEvent
from src.modules.hunting.kubelet import Kubelet
from src.modules.discovery.apiserver import ApiServerDiscovery
from src.modules.discovery.ports import PortDiscovery
from src.modules.hunting.apiserver import AccessApiServer
from src.modules.hunting.certificates import CertificateDiscovery
from src.modules.hunting.cvehunter import IsVulnerableToCVEAttack
import src


global hunt_started_lock
hunt_started_lock = threading.Lock()
hunt_started = False


def main():
    global hunt_started
    try:
        print("Hi, Kube-Six!")
        print("Scans security weaknesses in Kubernetes clusters!")
        hunt_started_lock.acquire()
        hunt_started = True
        hunt_started_lock.release()

        handler.publish_event(HuntStarted())
        handler.publish_event(HostScanEvent())
        
        handler.join()
    except KeyboardInterrupt:
        logging.debug("Kube-Hunter stopped by user")
    except EOFError:
        logging.error("\033[0;31mPlease run again with -it\033[0m")
    finally:
        hunt_started_lock.acquire()
        if hunt_started:
            hunt_started_lock.release()
            handler.publish_event(HuntFinished())
            handler.join()
            handler.free()
            logging.debug("Cleaned Queue")
        else:
            hunt_started_lock.release()



if __name__ == '__main__':
        main()

