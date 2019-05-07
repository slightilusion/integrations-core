# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
from requests.exceptions import ConnectionError, HTTPError, Timeout
from six import iteritems

from datadog_checks.base import AgentCheck
from datadog_checks.base.errors import CheckException

from . import common

# Tag templates
CLUSTER_TAG_TEMPLATE = "ambari_cluster:{}"
SERVICE_TAG = "ambari_service:"
COMPONENT_TAG = "ambari_component:"

# URL queries
COMPONENT_METRICS_QUERY = "/components?fields=metrics"
SERVICE_INFO_QUERY = "?fields=ServiceInfo"

# Response fields
METRICS_FIELD = "metrics"


class AmbariCheck(AgentCheck):
    def check(self, instance):
        base_url = instance.get("url", "")
        base_tags = instance.get("tags", [])
        whitelisted_services = instance.get("services", [])

        whitelisted_metrics = [str(h) for h in instance.get("metric_headers", [])]

        clusters = self.get_clusters(base_url)
        if instance.get("collect_host_metrics", True):
            self.get_host_metrics(base_url, clusters, base_tags)

        collect_service_metrics = instance.get("collect_service_metrics", True)
        collect_service_status = instance.get("collect_service_status", False)
        if collect_service_metrics or collect_service_status:
            self.get_service_metrics(
                base_url,
                clusters,
                whitelisted_services,
                whitelisted_metrics,
                base_tags,
                collect_service_metrics,
                collect_service_status,
            )

    def get_clusters(self, base_url):
        clusters_endpoint = common.CLUSTERS_URL.format(base_url=base_url)

        resp = self._make_request(clusters_endpoint)
        if resp is None:
            self._submit_service_checks("can_connect", self.CRITICAL, ["url:{}".format(base_url)])
            raise CheckException(
                "Couldn't connect to URL: {}. Please verify the address is reachable".format(clusters_endpoint)
            )

        self._submit_service_checks("can_connect", self.OK, ["url:{}".format(base_url)])
        return self._get_response_clusters(resp)

    def _get_response_clusters(self, resp):
        items = resp.get('items')
        self.log.warning("No clusters found")
        if not items:
            return []
        clusters = []
        for cluster in items:
            c = cluster.get('Clusters')
            if c:
                clusters.append(c.get('cluster_name'))
        return clusters

    def get_host_metrics(self, base_url, clusters, base_tags):
        external_tags = []
        for cluster in clusters:
            cluster_tag = CLUSTER_TAG_TEMPLATE.format(cluster)
            hosts_list = self._get_hosts_info(base_url, cluster)

            for host in hosts_list:
                h = host.get('Hosts')
                if not h:
                    self.log.warning("Unexpected response format for host list")
                    continue
                hostname = h.get('host_name')
                if not hostname:
                    self.log.warning("Unexpected response format for host list")
                    continue

                external_tags.append((hostname, {'ambari': [cluster_tag]}))
                host_metrics = host.get(METRICS_FIELD)
                if host_metrics is None:
                    self.warning("No metrics received for host {}".format(hostname))
                    continue

                metrics = self.flatten_host_metrics(host_metrics)
                for metric_name, value in iteritems(metrics):
                    metric_tags = base_tags + [cluster_tag]
                    if isinstance(value, float):
                        self._submit_gauge(metric_name, value, metric_tags, hostname)
                    else:
                        self.warning("Expected a float for {}, received {}".format(metric_name, value))
        self.set_external_tags(external_tags)

    def get_service_metrics(
        self,
        base_url,
        clusters,
        whitelisted_services,
        whitelisted_metrics,
        base_tags,
        collect_service_metrics,
        collect_service_status,
    ):
        for cluster in clusters:
            tags = base_tags + [CLUSTER_TAG_TEMPLATE.format(cluster)]
            for service, components in iteritems(whitelisted_services):
                service_tags = tags + [SERVICE_TAG + service.lower()]

                if collect_service_metrics:
                    self.get_component_metrics(
                        base_url, cluster, service, service_tags, [c.upper() for c in components], whitelisted_metrics
                    )
                if collect_service_status:
                    self.get_service_checks(base_url, cluster, service, service_tags)

    def get_service_checks(self, base_url, cluster, service, service_tags):
        service_info = self._get_service_checks_info(base_url, cluster, service, service_tags)
        for info in service_info:
            self._submit_service_checks("state", info['state'], info['tags'])

    def get_component_metrics(self, base_url, cluster, service, base_tags, component_whitelist, metric_whitelist):
        if not component_whitelist:
            return
        component_metrics_endpoint = common.create_endpoint(base_url, cluster, service, COMPONENT_METRICS_QUERY)
        components_response = self._make_request(component_metrics_endpoint)

        if components_response is None or 'items' not in components_response:
            self.log.warning("No components found for service {}.".format(service))
            return

        for component in components_response['items']:
            component_name = component['ServiceComponentInfo']['component_name']

            if component_name not in component_whitelist:
                self.log.warning('{} not found in {}:{}'.format(component_name, cluster, service))
                continue
            component_metrics = component.get(METRICS_FIELD)
            if component_metrics is None:
                self.log.warning("No metrics found for component {} for service {}".format(component_name, service))
                continue

            for header in metric_whitelist:
                if header not in component_metrics:
                    self.log.warning(
                        "No {} metrics found for component {} for service {}".format(header, component_name, service)
                    )
                    continue

                metrics = self.flatten_service_metrics(component_metrics[header], header)
                component_tag = COMPONENT_TAG + component_name.lower()
                for metric_name, value in iteritems(metrics):
                    metric_tags = base_tags + [component_tag]
                    if isinstance(value, float):
                        self._submit_gauge(metric_name, value, metric_tags)
                    else:
                        self.warning("Expected a float for {}, received {}".format(metric_name, value))

    def _get_hosts_info(self, base_url, cluster):
        hosts_endpoint = common.HOST_METRICS_URL.format(base_url=base_url, cluster_name=cluster)
        resp = self._make_request(hosts_endpoint)

        return resp.get('items')

    def _get_service_checks_info(self, base_url, cluster, service, service_tags):
        service_check_endpoint = common.create_endpoint(base_url, cluster, service, SERVICE_INFO_QUERY)
        service_info = []
        service_resp = self._make_request(service_check_endpoint)
        if service_resp is None:
            service_info.append({'state': self.CRITICAL, 'tags': service_tags})
            self.warning("No response received for service {}".format(service))
        else:
            state = service_resp.get('ServiceInfo').get('state')
            service_info.append({'state': common.STATUS[state], 'tags': service_tags})
        return service_info

    def _make_request(self, url):
        try:
            resp = self.http.get(url)
            return resp.json()
        except (HTTPError, ConnectionError) as e:
            self.warning(
                "Couldn't connect to URL: {} with exception: {}. Please verify the address is reachable".format(url, e)
            )
        except Timeout:
            self.warning("Connection timeout when connecting to {}".format(url))

    def _submit_gauge(self, name, value, tags, hostname=None):
        self.gauge('{}.{}'.format(common.METRIC_PREFIX, name), value, tags, hostname=hostname)

    def _submit_service_checks(self, name, value, tags):
        self.service_check('{}.{}'.format(common.METRIC_PREFIX, name), value, tags)

    @classmethod
    def flatten_service_metrics(cls, metric_dict, prefix):
        flat_metrics = {}
        for raw_metric_name, metric_value in iteritems(metric_dict):
            if isinstance(metric_value, dict):
                flat_metrics.update(cls.flatten_service_metrics(metric_value, prefix))
            else:
                metric_name = '{}.{}'.format(prefix, raw_metric_name) if prefix else raw_metric_name
                flat_metrics[metric_name] = metric_value
        return flat_metrics

    @classmethod
    def flatten_host_metrics(cls, metric_dict, prefix=""):
        flat_metrics = {}
        for raw_metric_name, metric_value in iteritems(metric_dict):
            metric_name = '{}.{}'.format(prefix, raw_metric_name) if prefix else raw_metric_name
            if raw_metric_name == "boottime":
                flat_metrics["boottime"] = metric_value
            elif isinstance(metric_value, dict):
                flat_metrics.update(cls.flatten_host_metrics(metric_value, metric_name))
            else:
                flat_metrics[metric_name] = metric_value
        return flat_metrics
