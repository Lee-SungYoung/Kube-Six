import logging
import json
import requests
import uuid
import ast
import subprocess
from ...core.events import handler
from ...core.events.common import Vulnerability, Event
from ..discovery.apiserver import ApiServer
from ...core.types import Hunter, ActiveHunter, KubernetesCluster, RemoteCodeExec, AccessRisk, InformationDisclosure, \
    PrivilegeEscalation, DenialOfService

""" Vulnerabilities """

class ServerApiVersionEndPointAccessPE(Vulnerability, Event):
    """CVE-2018-1002105"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Critical Privilege Escalation CVE", category=PrivilegeEscalation)
        self.evidence = evidence


class ServerApiVersionEndPointAccessDos(Vulnerability, Event):
    """CVE-2019-1002100"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Denial of Service to Kubernetes API Server", category=DenialOfService)
        self.evidence = evidence

class CheckCVE20191002101(Vulnerability, Event):
    """CVE-2019-1002101"""
    def __init__(self,evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="lead to command line argument injection", category=RemoteCodeExec)
        self.evidence = "hash"


@handler.subscribe(ApiServer)
class IsVulnerableToCVEAttack(Hunter):
    """CVE-2018-1002105"""
    def __init__(self, event):
        self.event = event
        self.headers = dict()
        # From within a Pod we may have extra credentials
        if self.event.auth_token:
            self.headers = {'Authorization': 'Bearer ' + self.event.auth_token}
        self.path = "https://{}:{}".format(self.event.host, self.event.port)
        self.api_server_evidence = ''
        self.k8sVersion = ''

    def get_api_server_version_end_point(self):
        logging.debug(self.event.host)
        if 'Authorization' in self.headers:
            logging.debug('Passive Hunter is attempting to access the API server version end point using the pod\'s service account token: \t%s', str(self.headers))
        else:
            logging.debug('Passive Hunter is attempting to access the API server version end point anonymously')
        try:
            res = requests.get("{path}/version".format(path=self.path),
                               headers=self.headers, verify=False)
            self.api_server_evidence = res.content
            resDict = ast.literal_eval(res.content)
            version = resDict["gitVersion"].split('.')
            first_two_minor_digits = eval(version[1])
            last_two_minor_digits = eval(version[2])
            logging.debug('Passive Hunter got version from the API server version end point: %d.%d', first_two_minor_digits, last_two_minor_digits)
            return [first_two_minor_digits, last_two_minor_digits]

        except (requests.exceptions.ConnectionError, KeyError):
            return None

    def check_cve_2018_1002105(self, api_version):
        first_two_minor_digists = api_version[0]
        last_two_minor_digists = api_version[1]

        if first_two_minor_digists == 10 and last_two_minor_digists < 11:
            return True
        elif first_two_minor_digists == 11 and last_two_minor_digists < 5:
            return True
        elif first_two_minor_digists == 12 and last_two_minor_digists < 3:
            return True
        elif first_two_minor_digists < 10:
            return True

        return False

    def check_cve_2019_1002100(self, api_version):
        first_two_minor_digists = api_version[0]
        last_two_minor_digists = api_version[1]

        if first_two_minor_digists == 11 and last_two_minor_digists < 8:
            return True
        elif first_two_minor_digists == 12 and last_two_minor_digists < 6:
            return True
        elif first_two_minor_digists == 13 and last_two_minor_digists < 4:
            return True
        elif first_two_minor_digists < 11:
            return True

        return False

    def check_cve_2019_1002101(self):
	tar_cmd = subprocess.check_output('kubectl exec myapp-pod -it md5sum /bin/tar',shell=True)
	tar_hash = tar_cmd.split(' ')
    	tar_org = 'ac32e3bd35515eab8f9cb5caab289b11'
    	if tar_org == tar_hash[0]:
    		return False
    	else:
    		return True

        return False
    def execute(self):
        api_version = self.get_api_server_version_end_point()

        if api_version:
            if self.check_cve_2018_1002105(api_version):
                self.publish_event(ServerApiVersionEndPointAccessPE(self.api_server_evidence))
            if self.check_cve_2019_1002100(api_version):
                self.publish_event(ServerApiVersionEndPointAccessDos(self.api_server_evidence))
            if self.check_cve_2019_1002101():
            	self.publish_event(CheckCVE20191002101(self.api_server_evidence))

