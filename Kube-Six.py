#!/usr/bin/env python
from __future__ import print_function
import requests
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
from src.core.events.common import HuntReported
from src.modules.discovery.hosts import HostScanEvent
from src.modules.hunting.kubelet import Kubelet
from src.modules.discovery.apiserver import ApiServerDiscovery
from src.modules.discovery.ports import PortDiscovery
from src.modules.hunting.apiserver import AccessApiServer
from src.modules.hunting.certificates import CertificateDiscovery
from src.modules.hunting.cvehunter import IsVulnerableToCVEAttack
import src

class Email:
    def __init__(self):
        self.email = ''
    def get_email(self):
        return self.email
    def set_email(self,email):
        self.email = email

email = Email()

global hunt_started_lock
hunt_started_lock = threading.Lock()
hunt_started = False


def main():
    global hunt_started
    URL = "http://hotsix.kro.kr/re_result.php"
    intro = "\x1b[1;34m\n\n"
    intro += "    Dg.     qDi                             iQBBBBi :BB:                   dKDRBdu.              :BB  QBg          BBY\n"
    intro += "    BBr     BBP             KBv            BBQv7jQv  JJ                    BBBMQBBBBs            .BQ  iU.          72\n"
    intro += "    BB      BBj    sgBPr   jBBBjr         iBQ        :. ij.    uu          BQ:    .BBu    LRQU.  .BB   ..    LDBgi ...   .2BBK:   .vr   .vr   :IQBP:\n"
    intro += "    BQQDQQRbBBs  EBBSudBB: DBBBR5          KBBBs     BBi.QB:  BB7          BBr     7BB  SBBiiBBP  BB  BBB  EBBqUEX QBg  BQB1uQBB  DBB   dBB  QBdirgv\n"
    intro += "    BBRgQQMEBBv LBB    .BB  BBr              rQBQB.  BBi  ZBsBE            BBr     vBB iBBi::UBB  QB  PBB LBB      BQS BBP    1BB jBQ   jBB  BQg.\n"
    intro += "    BB      BBs gBB     BB  BB7                 vQB  QBi  .QBQi            BB:     BBr 5BB:i7r:i  BB  PBB QBg      BBU BBr    rBB UBB   LBB   :PBBBi\n"
    intro += "    BBi     BBI  BB7   BBM  BBE           vBr. .DBQ  BQr bBB PBB           BBM7YIBQB7   BBr      .QB  gBB .BBL   : BQE rBB.  .BBr iBB.  BBB  r   BBB\n"
    intro += "    BB:     BQs   PBBBBBr   :BBBb         .BBBBBBj   BB:JBQ   bBB          QBBBBBgr      PBBBBBv .BB  XBR   EBBBBg QB1  .QBBBQQ.   UBBBXXBB .BBQBBS\n\x1b[1;m"
    print(intro)
    print("\x1b[1;34m    ================================================================================================================================================\x1b[1;m") 
    print("\x1b[1;34m    Hi, Kube-Six!\x1b[1;m")
    print("\x1b[1;34m    Kube-Six scans security weaknesses in Kubernetes clusters!\x1b[1;m")
    print("\x1b[1;34m    ================================================================================================================================================\n\x1b[1;m")
    print("\x1b[1;34m    write your email (ex. user@google.com)\x1b[1;m")
        
    USER_TOKEN = raw_input("\x1b[1;34m    My Email: \x1b[1;m")
    if not "@" in USER_TOKEN:
        USER_TOKEN = USER_TOKEN.split("@")[0]
        print("check your email form:)")
        return
    else:
        email.set_email(USER_TOKEN)
        res = requests.post(URL, data={'chk':'0', 'token': USER_TOKEN})
        if not "1" in res.text:
            print("\x1b[1;34mThis email already exists.\n Please Try again.\x1b[1;m")
            return
        else :
            try :
                hunt_started_lock.acquire()
                hunt_started = True
                hunt_started_lock.release()

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
                    handler.publish_event(HuntReported())
                    handler.join()
                    handler.free()
                    logging.debug("Cleaned Queue")
                else:
                    hunt_started_lock.release()
                        

if __name__ == '__main__':
        main()
