import logging

import __main__ 
from src.core.events import handler
from src.core.events.common import Event, Service, Vulnerability, HuntReported
import threading

global services_lock
services_lock = threading.Lock()
services = list()

global vulnerabilities_lock
vulnerabilities_lock = threading.Lock()
vulnerabilities = list()

hunters = handler.all_hunters

@handler.subscribe(Service)
@handler.subscribe(Vulnerability)
class Collector(object):
    def __init__(self, event=None):
        self.event = event

    def execute(self):
        global services
        global vulnerabilities
        bases = self.event.__class__.__mro__
        if Service in bases:
            services_lock.acquire()
            services.append(self.event)
            services_lock.release()

        elif Vulnerability in bases:
            vulnerabilities_lock.acquire()
            vulnerabilities.append(self.event)
            vulnerabilities_lock.release()

@handler.subscribe(HuntReported)
class SendFullReport(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        report = __main__.reporter.get_report()
        logging.info("\n{div}\n{report}".format(div="-" * 10, report=report))
        __main__.reporter.send_data()

