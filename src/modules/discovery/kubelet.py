import json
import logging
from enum import Enum
from ...core.types import Discovery, Kubelet

import requests
import urllib3

from ...core.events import handler
from ...core.events.common import OpenPortEvent, Vulnerability, Event, Service
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecureKubeletEvent(Service, Event):
    def __init__(self, cert=False, token=False, anonymous_auth=True, **kwargs):
        self.cert = cert
        self.token = token
        self.anonymous_auth = anonymous_auth
        Service.__init__(self, name="Kubelet API", **kwargs) 


class KubeletPorts(Enum):
    SECURED = 10250
    READ_ONLY = 10255

@handler.subscribe(OpenPortEvent, predicate= lambda x: x.port == 10255 or x.port == 10250)
class KubeletDiscovery(Discovery):
    def __init__(self, event):
        self.event = event

    def get_secure_access(self):
        logging.debug("Attempting to get kubelet secure access")
        ping_status = self.ping_kubelet()
        if ping_status == 200:
            self.publish_event(SecureKubeletEvent(secure=False))
        elif ping_status == 403: 
            self.publish_event(SecureKubeletEvent(secure=True))
        elif ping_status == 401:
            self.publish_event(SecureKubeletEvent(secure=True, anonymous_auth=False))

    def ping_kubelet(self):
        logging.debug("Attempting to get pod info from kubelet")
        try:
            return requests.get("https://{host}:{port}/pods".format(host=self.event.host, port=self.event.port), verify=False).status_code
        except Exception as ex:
            logging.debug("Failed pinging https port 10250 on {} : {}".format(self.event.host, ex.message))

    def execute(self):
        if self.event.port == KubeletPorts.SECURED.value:
            self.get_secure_access()
        elif self.event.port == KubeletPorts.READ_ONLY.value:
            self.get_read_only_access()
