import logging
import json
import requests
import uuid
import copy

from ...core.events import handler
from ...core.events.common import Vulnerability, Event
from ..discovery.apiserver import ApiServer
from ...core.types import Hunter, ActiveHunter, KubernetesCluster
from ...core.types import RemoteCodeExec, AccessRisk, InformationDisclosure, UnauthenticatedAccess


""" Vulnerabilities """


class ServerApiAccess(Vulnerability, Event):
    def __init__(self, evidence, using_token):
        if using_token:
            name = "Access to API using service account token"
            category = InformationDisclosure
        else:
            name = "Unauthenticated access to API"
            category = UnauthenticatedAccess
        Vulnerability.__init__(self, KubernetesCluster, name=name, category=category)
        self.evidence = evidence

class ApiServerPassiveHunterFinished(Event):
    def __init__(self, namespaces):
        print("hunting/apiserver_apiserverPassiveHunterFinished_init")
        self.namespaces = namespaces


@handler.subscribe(ApiServer)
class AccessApiServer(Hunter):
    def access_api_server(self):
        logging.debug('Passive Hunter is attempting to access the API at {host}:{port}'.format(host=self.event.host, 
            port=self.event.port))
        try:
            r = requests.get("{path}/api".format(path=self.path), headers=self.headers, verify=False)
            if r.status_code == 200 and r.content != '':
                return r.content
        except requests.exceptions.ConnectionError:
            pass
        return False

    def get_items(self, path):
        try: 
            items = []
            r = requests.get(path, headers=self.headers, verify=False)
            if r.status_code ==200:
                resp = json.loads(r.content)
                for item in resp["items"]:
                    items.append(item["metadata"]["name"])
                return items
        except (requests.exceptions.ConnectionError, KeyError):
            pass
        
        return None

    def get_pods(self, namespace=None):
        pods = []
        try:
            if namespace is None:
                r = requests.get("{path}/api/v1/pods".format(path=self.path),
                               headers=self.headers, verify=False)
            else:
                r = requests.get("{path}/api/v1/namespaces/{namespace}/pods".format(path=self.path),
                               headers=self.headers, verify=False)
            if r.status_code == 200:
                resp = json.loads(r.content)
                for item in resp["items"]:
                    name = item["metadata"]["name"].encode('ascii', 'ignore')
                    namespace = item["metadata"]["namespace"].encode('ascii', 'ignore')
                    pods.append({'name': name, 'namespace': namespace})

                return pods
        except (requests.exceptions.ConnectionError, KeyError):
            pass
        return None

    def execute(self):
        api = self.access_api_server()
        if api:
            self.publish_event(ServerApiAccess(api, self.with_token))

        namespaces = self.get_items("{path}/api/v1/namespaces".format(path=self.path))
        if namespaces:
            self.publish_event(ListNamespaces(namespaces, self.with_token))

        roles = self.get_items("{path}/apis/rbac.authorization.k8s.io/v1/roles".format(path=self.path))
        if roles:
            self.publish_event(ListRoles(roles, self.with_token))

        cluster_roles = self.get_items("{path}/apis/rbac.authorization.k8s.io/v1/clusterroles".format(path=self.path))
        if cluster_roles:
            self.publish_event(ListClusterRoles(cluster_roles, self.with_token))

        pods = self.get_pods()
        if pods:
            self.publish_event(ListPodsAndNamespaces(pods, self.with_token))

        self.publish_event(ApiServerPassiveHunterFinished(namespaces))

