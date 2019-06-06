from ...core.types import Hunter, KubernetesCluster, InformationDisclosure
from ...core.events import handler
from ...core.events.common import Vulnerability, Event, Service

import ssl
import logging
import base64
import re

from socket import socket

email_pattern = re.compile(r"([a-z0-9]+@[a-z0-9]+\.[a-z0-9]+)")

@handler.subscribe(Service)
class CertificateDiscovery(Hunter):
    def __init__(self, event):
        self.event = event

    def execute(self):
        try:
            logging.debug("Passive hunter is attempting to get server certificate")
            addr = (str(self.event.host), self.event.port)
            cert = ssl.get_server_certificate(addr)
        except ssl.SSLError as e:
            return
        c = cert.strip(ssl.PEM_HEADER).strip(ssl.PEM_FOOTER)
        certdata = base64.decodestring(c)
        emails = re.findall(email_pattern, certdata)
        for email in emails:
            self.publish_event( CertificateEmail(email=email) )
