from __future__ import print_function

from prettytable import ALL, PrettyTable

from .collector import services, vulnerabilities, hunters, handler, services_lock, vulnerabilities_lock
import logging
EVIDENCE_PREVIEW = 40
MAX_TABLE_WIDTH = 20

class BaseReporter(object):
    def get_nodes(self):
        nodes = list()
        node_locations = set()
        services_lock.acquire()
        for service in services:
            node_location = str(service.host)
            if node_location not in node_locations:
                nodes.append({"type": "Node/Master", "location": str(service.host)})
                node_locations.add(node_location)
        services_lock.release()
        return nodes

    def get_services(self):
        services_lock.acquire()
        services_data = [{"service": service.get_name(),
                 "location": "{}:{}{}".format(service.host, service.port, service.get_path()),
                 "description": service.explain()}
                for service in services]
        services_lock.release()
        return services_data

    def get_vulnerabilities(self):
        vulnerabilities_lock.acquire()
        vulnerabilities_data = [{"location": vuln.location(),
                 "category": vuln.category.name,
                 "severity": vuln.get_severity(),
                 "vulnerability": vuln.get_name(),
                 "description": vuln.explain(),
                 "version": str(vuln.evidence)}
                for vuln in vulnerabilities]
        vulnerabilities_lock.release()
        return vulnerabilities_data

    def get_hunter_statistics(self):
        hunters_data = list()
        for hunter, docs in hunters.items():
            if not Discovery in hunter.__mro__:
                name, doc = hunter.parse_docs(docs)
                hunters_data.append({"name": name, "description": doc, "vulnerabilities": hunter.publishedVulnerabilities})
        return hunters_data

class PlainReporter(BaseReporter):
    def get_report(self):
        output = ""

        vulnerabilities_lock.acquire()
        vulnerabilities_len = len(vulnerabilities)
        vulnerabilities_lock.release()

        hunters_len = len(hunters.items())

        services_lock.acquire()
        services_len = len(services)
        services_lock.release()

        if services_len:
            output += self.nodes_table()
            output += self.services_table()
            if vulnerabilities_len:
                output += self.vulns_table()
            else:
                output += "\nNo vulnerabilities were found"
        else:
            print("\nKube Hunter couldn't find any clusters")
        return output

    def nodes_table(self):
        nodes_table = PrettyTable(["Type", "Location"], hrules=ALL)
        nodes_table.align = "l"
        nodes_table.max_width = MAX_TABLE_WIDTH
        nodes_table.padding_width = 1
        nodes_table.sortby = "Type"
        nodes_table.reversesort = True
        nodes_table.header_style = "upper"
        id_memory = list()
        services_lock.acquire()
        for service in services:
            if service.event_id not in id_memory:
                nodes_table.add_row(["Node/Master", service.host])
                id_memory.append(service.event_id)
        nodes_ret = "\nNodes\n{}\n".format(nodes_table)
        services_lock.release()
        return nodes_ret

    def services_table(self):
        services_table = PrettyTable(["Service", "Location"], hrules=ALL)
        services_table.align = "l"
        services_table.max_width = MAX_TABLE_WIDTH
        services_table.padding_width = 1
        services_table.sortby = "Service"
        services_table.reversesort = True
        services_table.header_style = "upper"
        services_lock.acquire()
        for service in services:
            services_table.add_row([service.get_name(), "{}:{}{}".format(service.host, service.port, service.get_path())])
        detected_services_ret = "\nDetected Services\n{}\n".format(services_table)
        services_lock.release()
        return detected_services_ret

    def vulns_table(self):
        column_names = ["Location", "Category", "Vulnerability", "Description", "Evidence"]
        vuln_table = PrettyTable(column_names, hrules=ALL)
        vuln_table.align = "l"
        vuln_table.max_width = MAX_TABLE_WIDTH
        vuln_table.sortby = "Category"
        vuln_table.reversesort = True
        vuln_table.padding_width = 1
        vuln_table.header_style = "upper"

        vulnerabilities_lock.acquire()
        for vuln in vulnerabilities:
            row = [vuln.location(), vuln.category.name, vuln.get_name(), vuln.explain()]
            evidence = str(vuln.evidence)[:EVIDENCE_PREVIEW] + "..." if len(str(vuln.evidence)) > EVIDENCE_PREVIEW else str(vuln.evidence)
            row.append(evidence)
            vuln_table.add_row(row)
        vulnerabilities_lock.release()
        return "\nVulnerabilities\n{}\n".format(vuln_table)

