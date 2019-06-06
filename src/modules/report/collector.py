import logging

import __main__ 
from src.core.events import handler
from src.core.events.common import Event, Service, Vulnerability, HuntFinished, HuntStarted
import threading

global services_lock
services_lock = threading.Lock()
services = list()

global vulnerabilities_lock
vulnerabilities_lock = threading.Lock()
vulnerabilities = list()

hunters = handler.all_hunters

def console_trim(text, prefix=' '):
    a = text.split(" ")
    b = a[:]
    total_length = 0
    count_of_inserts = 0
    for index, value in enumerate(a):
        if (total_length + (len(value) + len(prefix))) >= 80:
            b.insert(index + count_of_inserts, '\n')
            count_of_inserts += 1
            total_length = 0
        else:
            total_length += len(value) + len(prefix)
    return '\n'.join([prefix + line.strip(' ') for line in ' '.join(b).split('\n')])

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


class TablesPrinted(Event):
    pass


@handler.subscribe(HuntFinished)
class SendFullReport(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        report = __main__.reporter.get_report()
        logging.info("\n{div}\n{report}".format(div="-" * 10, report=report))
        handler.publish_event(TablesPrinted())


@handler.subscribe(HuntStarted)
class StartedInfo(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        return
