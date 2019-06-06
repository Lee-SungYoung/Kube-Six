import logging

class HunterBase(object):
    publishedVulnerabilities = 0
    def publish_event(self, event):
        handler.publish_event(event, caller=self)

class ActiveHunter(HunterBase):
    pass


class Hunter(HunterBase):
    pass


class Discovery(HunterBase):
    pass


class KubernetesCluster():
    """Kubernetes Cluster"""
    name = "Kubernetes Cluster"


class Kubelet(KubernetesCluster):
    """Kubelet"""
    name = "Kubelet"


class Azure(KubernetesCluster):
    name = "Azure"


class InformationDisclosure(object):
    name = "Information Disclosure"


class RemoteCodeExec(object):
    name = "Remote Code Execution"


class IdentityTheft(object):
    name = "Identity Theft"


class UnauthenticatedAccess(object):
    name = "Unauthenticated Access"


class AccessRisk(object):
    name = "Access Risk"


class PrivilegeEscalation(KubernetesCluster):
    name = "Privilege Escalation"

class DenialOfService(object):
    name = "Denial of Service"

from .events import handler # import is in the bottom to break import loops
