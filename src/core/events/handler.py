import logging
import time
from abc import ABCMeta
from collections import defaultdict
from queue import Queue
from threading import Lock, Thread

from ..types import ActiveHunter, Hunter, HunterBase

from ...core.events.common import HuntReported, Vulnerability
import threading

global queue_lock
queue_lock = Lock()

class EventQueue(Queue, object):
    def __init__(self, num_worker=10):
        super(EventQueue, self).__init__()
        self.passive_hunters = dict()
        self.active_hunters = dict()
        self.all_hunters = dict()

        self.hooks = defaultdict(list)
        self.running = True
        self.workers = list()

        for i in range(num_worker):
            t = Thread(target=self.worker)
            t.daemon = True
            t.start()
            self.workers.append(t)
        t = Thread(target=self.notifier)
        t.daemon = True
        t.start()

    def subscribe(self, event, hook=None, predicate=None):
        def wrapper(hook):
            self.subscribe_event(event, hook=hook, predicate=predicate)
            return hook

        return wrapper

    def subscribe_event(self, event, hook=None, predicate=None):
        if ActiveHunter in hook.__mro__:
            return

        elif HunterBase in hook.__mro__:
            self.passive_hunters[hook] = hook.__doc__

        if HunterBase in hook.__mro__:
            self.all_hunters[hook] = hook.__doc__

        if hook not in self.hooks[event]:
            self.hooks[event].append((hook, predicate))
            logging.debug('{} subscribed to {}'.format(hook, event))

    def publish_event(self, event, caller=None):
        logging.debug('Event {} got published with {}'.format(event.__class__, event))
        for hooked_event in self.hooks.keys():
            if hooked_event in event.__class__.__mro__:
                for hook, predicate in self.hooks[hooked_event]:
                    if predicate and not predicate(event):
                        continue

                    if caller:
                        event.previous = caller.event

                    self.put(hook(event))

    def worker(self):
        while self.running:
            queue_lock.acquire()
            hook = self.get()
            queue_lock.release()
            try:
                hook.execute()
            except Exception as ex:
                logging.debug(ex)
            self.task_done()
        logging.debug("closing thread...")

    def notifier(self):
        time.sleep(2)
        while self.unfinished_tasks > 0:
            logging.debug("{} tasks left".format(self.unfinished_tasks))
            time.sleep(3)

    def free(self):
        self.running = False
        with self.mutex:
            self.queue.clear()

handler = EventQueue(800)
