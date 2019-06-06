import os
import json
import logging
import socket
import sys
import time
from enum import Enum

import requests
from netaddr import IPNetwork

from netifaces import AF_INET, ifaddresses, interfaces

from ...core.events import handler
from ...core.events.common import Event, NewHostEvent, Vulnerability
from ...core.types import Discovery, InformationDisclosure, Azure

class HostScanEvent(Event):
    def __init__(self, pod=False, active=False, predefined_hosts=list()):
        self.active = active # flag to specify whether to get actual data from vulnerabilities
        self.predefined_hosts = predefined_hosts

class HostDiscoveryHelpers:
    @staticmethod
    def get_cloud(host):
        try:
            logging.debug("Checking whether the cluster is deployed on azure's cloud")
            metadata = requests.get("http://www.azurespeed.com/api/region?ipOrUrl={ip}".format(ip=host)).text
        except requests.ConnectionError as e:
            logging.info("- unable to check cloud: {0}".format(e))
            return
        if "cloud" in metadata:
            return json.loads(metadata)["cloud"]

    # generator, generating a subnet by given a cidr
    @staticmethod
    def generate_subnet(ip, sn="24"):
        logging.debug("HostDiscoveryHelpers.generate_subnet {0}/{1}".format(ip, sn))
        subnet = IPNetwork('{ip}/{sn}'.format(ip=ip, sn=sn))
        for ip in IPNetwork(subnet):
            logging.debug("HostDiscoveryHelpers.generate_subnet yielding {0}".format(ip))
            yield ip


@handler.subscribe(HostScanEvent)
class HostDiscovery(Discovery):
    def __init__(self, event):
        self.event = event

    def execute(self):
        self.scan_interfaces()
 
    def scan_interfaces(self):
        try:
            logging.debug("HostDiscovery hunter attempting to get external IP address")
            external_ip = requests.get("http://canhazip.com").text # getting external ip, to determine if cloud cluster
        except requests.ConnectionError as e:
            logging.debug("unable to determine local IP address: {0}".format(e))
            logging.info("~ default to 127.0.0.1")
            external_ip = "127.0.0.1"
        cloud = HostDiscoveryHelpers.get_cloud(external_ip)
        for ip in self.generate_interfaces_subnet():
            handler.publish_event(NewHostEvent(host=ip, cloud=cloud))

    def generate_interfaces_subnet(self, sn='24'):
        for ifaceName in interfaces():
            for ip in [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [])]:
                if not self.event.localhost and InterfaceTypes.LOCALHOST.value in ip.__str__():
                    continue
                for ip in HostDiscoveryHelpers.generate_subnet(ip, sn):
                    yield ip
                    
class InterfaceTypes(Enum):
    LOCALHOST = "127"
