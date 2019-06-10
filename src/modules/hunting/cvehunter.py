import threading
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
    PrivilegeEscalation, DenialOfService, UnauthenticatedAccess

""" Vulnerabilities """
global final_pods
final_pods = ''
global check_lock
check_lock = threading.Lock()
global check
check=0

class ServerApiVersionEndPointAccessPE(Vulnerability, Event):
    """CVE-2018-1002105"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Critical Privilege Escalation CVE", category=PrivilegeEscalation)
        self.evidence = evidence[37:60]


class ServerApiVersionEndPointAccessDos(Vulnerability, Event):
    """CVE-2019-1002100"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Denial of Service to Kubernetes API Server", category=DenialOfService)
        self.evidence = evidence[37:60]

class CheckCVE20181002101(Vulnerability, Event):
    """CVE-2018-1002101"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="lead to command line argument injection", category=RemoteCodeExec)
        self.evidence = evidence[37:60]

class CheckCVE20199946(Vulnerability, Event):
    """CVE-2019-9946"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="Unauthenticated Access", category=UnauthenticatedAccess)
        self.evidence = evidence[37:60]

class CheckCVE201911243(Vulnerability, Event):
    """CVE-2019-11243"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="remains service account credentials", category=InformationDisclosure)
        self.evidence = evidence[37:60]

class CheckCVE201911244(Vulnerability, Event):
    """CVE-2019-11244"""
    def __init__(self, evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="--cache-dir may be modified by other users/groups", category=UnauthenticatedAccess)
        self.evidence = evidence[37:60]

class CheckCVE20191002101(Vulnerability, Event):
    """CVE-2019-1002101"""
    def __init__(self,evidence):
        Vulnerability.__init__(self, KubernetesCluster, name="run any code and output unexpected, malicious results", category=RemoteCodeExec)
        self.evidence = "* vulnerable pods * \n" + evidence


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
        pods = subprocess.check_output('kubectl get pods',shell=True)
        pods = pods.split('\n')
        check_lock.acquire()
        global final_pods
        global check
        for i in range(1, len(pods)-1):
            pod = pods[i][:14]
            pod=pod.split(' ')[0]
            cmd = 'kubectl exec '
            cmd += pod
            cmd += ' -it md5sum /bin/tar'
            tar_cmd = subprocess.check_output(cmd,shell=True)
            tar_hash = tar_cmd.split(' ')[0]
            tar_org = 'ac32e3bd35515eab8f9cb5caab289b11'
    	    if tar_org == tar_hash:
                print("same")
            else:
                final_pods += pod
                final_pods += '\n'
                check = check +1
                
        if check != 0:
            check = 0
            check_lock.release()
            return True
        else:
            check_lock.release()
            return False

    def check_cve_2018_1002101(self, api_version):
        first_two_minor_digists = api_version[0]
        last_two_minor_digists = api_version[1]

        if first_two_minor_digists == 11 and last_two_minor_digists < 9:
            return True
        elif first_two_minor_digists == 12 and last_two_minor_digists < 7:
            return True
        elif first_two_minor_digists == 13 and last_two_minor_digists < 4:
            return True
        elif first_two_manor_digists == 14 and last_two_minor_digists < 1:
            return True
        elif first_two_minor_digists < 11:
            return True

        return False

    def check_cve_2019_9946(self, api_version):
        first_two_minor_digists = api_version[0]
        last_two_minor_digists = api_version[1]

        if first_two_minor_digists == 11 and last_two_minor_digists < 9:
            return True
        elif first_two_minor_digists == 12 and last_two_minor_digists < 6:
            return True
        elif first_two_minor_digists == 13: 
            if last_two_minor_digists < 4 or last_two_minor_digists == 6:
                return True
        elif first_two_manor_digists == 14 and last_two_minor_digists < 1:
            return True
        elif first_two_minor_digists < 11:
            return True

        return False

    def check_cve_2019_11243(self, api_version):
        first_two_minor_digists = api_version[0]
        last_two_minor_digists = api_version[1]

        if first_two_minor_digists == 12 and last_two_minor_digists < 5:
            return True
        elif first_two_minor_digists == 13 and last_two_minor_digists == 0:
            return True
        
        return False

    def check_cve_2019_11244(self, api_version):
        first_two_minor_digists = api_version[0]
        last_two_minor_digists = api_version[1]

        if first_two_minor_digists == 11 and last_two_minor_digists < 10:
            return True
        elif first_two_minor_digists == 12 and last_two_minor_digists < 7:
            return True
        elif first_two_minor_digists == 13 and last_two_minor_digists < 4:
            return True
        elif first_two_manor_digists == 14 and last_two_minor_digists < 1:
            return True
        elif first_two_minor_digists < 11 and first_two_minor_digists > 7:
            return True

        return False

    def execute(self):
        api_version = self.get_api_server_version_end_point()
        global final_pods
        if api_version:
            if self.check_cve_2019_1002101():
            	self.publish_event(CheckCVE20191002101(final_pods))
                final_pods = ''
            if self.check_cve_2019_9946(api_version):
                self.publish_event(CheckCVE20199946(self.api_server_evidence))
            if self.check_cve_2019_11243(api_version):
                self.publish_event(CheckCVE201911243(self.api_server_evidence))
            if self.check_cve_2019_11244(api_version):
                self.publish_event(CheckCVE201911244(self.api_server_evidence))
            if self.check_cve_2018_1002101(api_version):
                self.publish_event(CheckCVE20181002101(self.api_server_evidence))
            if self.check_cve_2018_1002105(api_version):
                self.publish_event(ServerApiVersionEndPointAccessPE(self.api_server_evidence))
            if self.check_cve_2019_1002100(api_version):
                self.publish_event(ServerApiVersionEndPointAccessDos(self.api_server_evidence))
        else: return

