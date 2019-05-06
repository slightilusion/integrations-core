# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
from __future__ import division

import ssl
from collections import defaultdict
from datetime import datetime
from itertools import chain
from os.path import expanduser, isdir

import vertica_python as vertica
from vertica_python.vertica.column import timestamp_tz_parse

from datadog_checks.base import AgentCheck, is_affirmative
from datadog_checks.base.utils.containers import iter_unique

from . import views
from .utils import node_state_to_service_check

# Python 3 only
PROTOCOL_TLS_CLIENT = getattr(ssl, 'PROTOCOL_TLS_CLIENT', ssl.PROTOCOL_TLS)


class VerticaCheck(AgentCheck):
    __NAMESPACE__ = 'vertica'
    SERVICE_CHECK_CONNECT = 'can_connect'
    SERVICE_CHECK_NODE_STATE = 'node_state'

    def __init__(self, name, init_config, instances):
        super(VerticaCheck, self).__init__(name, init_config, instances)

        self._db = self.instance.get('db', '')
        self._server = self.instance.get('server', '')
        self._port = self.instance.get('port', 5433)
        self._username = self.instance.get('username', '')
        self._password = self.instance.get('password', '')
        self._timeout = float(self.instance.get('timeout', 10))
        self._tags = self.instance.get('tags', [])

        self._tls_verify = is_affirmative(self.instance.get('tls_verify', False))
        self._validate_hostname = is_affirmative(self.instance.get('validate_hostname', True))

        self._cert = self.instance.get('cert', '')
        if self._cert:  # no cov
            self._cert = expanduser(self._cert)
            self._tls_verify = True

        self._private_key = self.instance.get('private_key', '')
        if self._private_key:  # no cov
            self._private_key = expanduser(self._private_key)

        self._cafile = None
        self._capath = None
        ca_cert = self.instance.get('ca_cert', '')
        if ca_cert:  # no cov
            ca_cert = expanduser(ca_cert)
            if isdir(ca_cert):
                self._capath = ca_cert
            else:
                self._cafile = ca_cert

            self._tls_verify = True

        custom_queries = self.instance.get('custom_queries', [])
        use_global_custom_queries = self.instance.get('use_global_custom_queries', True)

        # Handle overrides
        if use_global_custom_queries == 'extend':
            custom_queries.extend(self.init_config.get('global_custom_queries', []))
        elif 'global_custom_queries' in self.init_config and is_affirmative(use_global_custom_queries):
            custom_queries = self.init_config.get('global_custom_queries', [])

        # Deduplicate
        self._custom_queries = list(iter_unique(custom_queries))

        # Add global database tag
        self._tags.append('db:{}'.format(self._db))

        # We'll connect on the first check run
        self._conn = None

        # Cache database results for re-use among disparate functions
        self._view = defaultdict(list)

    def check(self, instance):
        if self._conn is None:
            connection = self.get_connection()
            if connection is None:
                return

            self._conn = connection

        # The order of queries is important as results are cached for later re-use
        try:
            self.query_licenses()
            self.query_license_audits()
            self.query_nodes()
        finally:
            self._view.clear()

    def query_licenses(self):
        # https://www.vertica.com/docs/9.2.x/HTML/Content/Authoring/SQLReferenceManual/SystemTables/CATALOG/LICENSES.htm
        for db_license in self.iter_rows(views.Licenses):
            tags = ['license_name:{}'.format(db_license['name'])]
            tags.extend(self._tags)

            expiration = db_license['end_date']
            if expiration and expiration != 'Perpetual':
                expiration = timestamp_tz_parse(expiration)
                seconds_until_expiration = (expiration - datetime.now(tz=expiration.tzinfo)).total_seconds()
            else:
                seconds_until_expiration = -1

            self.gauge('license.expiration', seconds_until_expiration, tags=tags)

    def query_license_audits(self):
        # https://www.vertica.com/docs/9.2.x/HTML/Content/Authoring/SQLReferenceManual/SystemTables/CATALOG/LICENSE_AUDITS.htm
        for license_audit in self.iter_rows(views.LicenseAudits):
            last_audit = license_audit['audit_start_timestamp']
            if last_audit:
                seconds_since_last_audit = (datetime.now(tz=last_audit.tzinfo) - last_audit).total_seconds()
            else:
                seconds_since_last_audit = -1
            self.gauge('license.latest_audit', seconds_since_last_audit, tags=self._tags)

            size = int(license_audit['license_size_bytes'])
            used = int(license_audit['database_size_bytes'])
            self.gauge('license.size', size, tags=self._tags)
            self.gauge('license.used', used, tags=self._tags)
            self.gauge('license.usable', size - used, tags=self._tags)
            self.gauge('license.utilized', used / size * 100, tags=self._tags)

    def query_nodes(self):
        # https://www.vertica.com/docs/9.2.x/HTML/Content/Authoring/SQLReferenceManual/SystemTables/CATALOG/NODES.htm
        num_nodes = 0
        for node in self.iter_rows(views.Nodes):
            num_nodes += 1
            tags = ['node_name:{}'.format(node['node_name'])]
            tags.extend(self._tags)

            node_state = node['node_state']
            self.service_check(
                self.SERVICE_CHECK_NODE_STATE, node_state_to_service_check(node_state), message=node_state, tags=tags
            )

        allowed_nodes = self._view[views.Licenses][0]['node_restriction']
        self.gauge('nodes.allowed', allowed_nodes, tags=self._tags)
        self.gauge('nodes.used', num_nodes, tags=self._tags)
        self.gauge('nodes.available', allowed_nodes - num_nodes, tags=self._tags)

    def query_custom(self):
        for custom_query in self._custom_queries:
            metric_prefix = custom_query.get('metric_prefix')
            if not metric_prefix:  # no cov
                self.log.error('Custom query field `metric_prefix` is required')
                continue
            metric_prefix = metric_prefix.rstrip('.')

            query = custom_query.get('query')
            if not query:  # no cov
                self.log.error('Custom query field `query` is required for metric_prefix `{}`'.format(metric_prefix))
                continue

            columns = custom_query.get('columns')
            if not columns:  # no cov
                self.log.error('Custom query field `columns` is required for metric_prefix `{}`'.format(metric_prefix))
                continue

            self.log.debug('Running query for metric_prefix `{}`: `{}`'.format(metric_prefix, query))
            cursor = self._conn.cursor()
            cursor.execute(query)

            rows = cursor.iterate()

            # Trigger query execution
            try:
                first_row = next(rows)
            except Exception as e:  # no cov
                self.log.error('Error executing query for metric_prefix `{}`: `{}`'.format(metric_prefix, e))
                continue

            for row in chain((first_row,), rows):
                if not row:  # no cov
                    self.log.debug(
                        'Query result for metric_prefix `{}`: returned an empty result'.format(metric_prefix)
                    )
                    continue

                if len(columns) != len(row):  # no cov
                    self.log.error(
                        'Query result for metric_prefix `{}`: expected {} columns, got {}'.format(
                            metric_prefix, len(columns), len(row)
                        )
                    )
                    continue

                metric_info = []
                query_tags = list(self._tags)
                query_tags.extend(custom_query.get('tags', []))

                for column, value in zip(columns, row):
                    # Columns can be ignored via configuration.
                    if not column:  # no cov
                        continue

                    name = column.get('name')
                    if not name:  # no cov
                        self.log.error('Column field `name` is required for metric_prefix `{}`'.format(metric_prefix))
                        break

                    column_type = column.get('type')
                    if not column_type:  # no cov
                        self.log.error(
                            'Column field `type` is required for column `{}` '
                            'of metric_prefix `{}`'.format(name, metric_prefix)
                        )
                        break

                    if column_type == 'tag':
                        query_tags.append('{}:{}'.format(name, value))
                    else:
                        if not hasattr(self, column_type):
                            self.log.error(
                                'Invalid submission method `{}` for metric column `{}` of '
                                'metric_prefix `{}`'.format(column_type, name, metric_prefix)
                            )
                            break
                        try:
                            metric_info.append(('{}.{}'.format(metric_prefix, name), float(value), column_type))
                        except (ValueError, TypeError):  # no cov
                            self.log.error(
                                'Non-numeric value `{}` for metric column `{}` of '
                                'metric_prefix `{}`'.format(value, name, metric_prefix)
                            )
                            break

                # Only submit metrics if there were absolutely no errors - all or nothing.
                else:
                    for info in metric_info:
                        metric, value, method = info
                        getattr(self, method)(metric, value, tags=query_tags)

    def get_connection(self):
        connection_options = {
            'database': self._db,
            'host': self._server,
            'port': self._port,
            'user': self._username,
            'password': self._password,
            'connection_timeout': self._timeout,
        }

        if self._tls_verify:  # no cov
            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext
            # https://docs.python.org/3/library/ssl.html#ssl.PROTOCOL_TLS
            tls_context = ssl.SSLContext(protocol=PROTOCOL_TLS_CLIENT)

            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.verify_mode
            tls_context.verify_mode = ssl.CERT_REQUIRED

            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname
            tls_context.check_hostname = self._validate_hostname

            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_verify_locations
            if self._cafile or self._capath:
                tls_context.load_verify_locations(self._cafile, self._capath, None)

            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_default_certs
            else:
                tls_context.load_default_certs(ssl.Purpose.SERVER_AUTH)

            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_cert_chain
            if self._cert:
                tls_context.load_cert_chain(self._cert, keyfile=self._private_key)

            connection_options['ssl'] = tls_context

        try:
            connection = vertica.connect(**connection_options)
        except Exception as e:
            self.log.error('Unable to connect to database `{}` as user `{}`: {}'.format(self._db, self._username, e))
            self.service_check(self.SERVICE_CHECK_CONNECT, self.CRITICAL, tags=self._tags)
        else:
            self.service_check(self.SERVICE_CHECK_CONNECT, self.OK, tags=self._tags)
            return connection

    def iter_rows(self, view):
        cursor = self._conn.cursor('dict')
        cursor.execute(view.query)

        for row in cursor.iterate():
            self._view[view].append(row)

            yield row
