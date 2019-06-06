import json
import logging
from enum import Enum

import requests
import urllib3

from ...core.events import handler
from ...core.events.common import Vulnerability, Event
from ..discovery.kubelet import SecureKubeletEvent
from ...core.types import Hunter, ActiveHunter, KubernetesCluster, Kubelet, InformationDisclosure, RemoteCodeExec, AccessRisk
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


""" Vulnerabilities """
@handler.subscribe(SecureKubeletEvent)        
class SecureKubeletPortHunter(Hunter):
    def __init__(self, event):
        self.event = event
        self.session = requests.Session()
        if self.event.secure:
            self.session.headers.update({"Authorization": "Bearer {}".format(self.event.auth_token)})
            # self.session.cert = self.event.client_cert
        self.path = "https://{}:{}/".format(self.event.host, 10250)
        self.kubehunter_pod = {"name": "kube-hunter", "namespace": "default", "container": "kube-hunter"}
        self.pods_endpoint_data = ""

    def get_pods_endpoint(self):
        response = self.session.get(self.path + "pods", verify=False)
        if "items" in response.text:
            return json.loads(response.text)

    def check_healthz_endpoint(self):
        r = requests.get(self.path + "healthz", verify=False)
        return r.text if r.status_code == 200 else False

    def execute(self):
        if self.event.anonymous_auth:
            self.publish_event(AnonymousAuthEnabled())

        self.pods_endpoint_data = self.get_pods_endpoint()
        healthz = self.check_healthz_endpoint() 
        if self.pods_endpoint_data:
            self.publish_event(ExposedPodsHandler(count=len(self.pods_endpoint_data["items"])))
        if healthz:
            self.publish_event(ExposedHealthzHandler(status=healthz)) 
        self.test_handlers()

    def test_handlers(self):
        # if kube-hunter runs in a pod, we test with kube-hunter's pod        
        pod = self.kubehunter_pod if config.pod else self.get_random_pod()
        if pod:
            debug_handlers = self.DebugHandlers(self.path, pod=pod, session=self.session)
            try:
                running_pods = debug_handlers.test_running_pods()
                if running_pods:
                    self.publish_event(ExposedRunningPodsHandler(count=len(running_pods["items"])))            
                if debug_handlers.test_container_logs():
                    self.publish_event(ExposedContainerLogsHandler())
                if debug_handlers.test_exec_container():
                    self.publish_event(ExposedExecHandler())      
                if debug_handlers.test_run_container():
                    self.publish_event(ExposedRunHandler())
                if debug_handlers.test_port_forward():
                    self.publish_event(ExposedPortForwardHandler()) # not implemented            
                if debug_handlers.test_attach_container():
                    self.publish_event(ExposedAttachHandler())
            except Exception as ex:
                logging.debug(str(ex.message))
        else:
            pass # no pod to check on.

    # trying to get a pod from default namespace, if doesnt exist, gets a kube-system one
    def get_random_pod(self):
        if self.pods_endpoint_data: 
            pods_data = self.pods_endpoint_data["items"]
            # filter running kubesystem pod
            is_default_pod = lambda pod: pod["metadata"]["namespace"] == "default" and pod["status"]["phase"] == "Running"        
            is_kubesystem_pod = lambda pod: pod["metadata"]["namespace"] == "kube-system" and pod["status"]["phase"] == "Running"
            pod_data = next((pod_data for pod_data in pods_data if is_default_pod(pod_data)), None)
            if not pod_data:
                pod_data = next((pod_data for pod_data in pods_data if is_kubesystem_pod(pod_data)), None)
            
            container_data = (container_data for container_data in pod_data["spec"]["containers"]).next()
            return {
                "name": pod_data["metadata"]["name"],
                "container": container_data["name"],
                "namespace": pod_data["metadata"]["namespace"]
            }

