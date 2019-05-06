# Agent Check: Vertica

## Overview

This check monitors [Vertica][1] through the Datadog Agent.

## Setup

### Installation

The Vertica check is included in the [Datadog Agent][2] package.

The user used to connect to the database must be granted the [SYSMONITOR][3] role in order to access the monitoring system tables.

Additionally, as the metrics for current license usage use the values from the most recent [audit][4], it is recommended to schedule it to occur as often and with as most accuracy as possible. For more information, see [this][5].

### Configuration

1. Edit the `vertica.d/conf.yaml` file, in the `conf.d/` folder at the root of your Agent's configuration directory to start collecting your vertica performance data. See the [sample vertica.d/conf.yaml][6] for all available configuration options.

2. [Restart the Agent][7].

### Validation

[Run the Agent's status subcommand][8] and look for `vertica` under the Checks section.

## Data Collected

### Metrics

See [metadata.csv][9] for a list of metrics provided by this integration.

### Service Checks

- `vertica.can_connect` returns `OK` if the Agent is able to connect to the monitored Vertica database, or `CRITICAL` otherwise.
- `vertica.node_state` returns `OK` if the monitored Vertica database is UP, `WARNING` for states that are on a possible path to UP, or `CRITICAL` otherwise.

### Events

Vertica does not include any events.

## Troubleshooting

Need help? Contact [Datadog support][10].

[1]: https://www.vertica.com
[2]: https://docs.datadoghq.com/agent
[3]: https://www.vertica.com/docs/9.2.x/HTML/Content/Authoring/AdministratorsGuide/DBUsersAndPrivileges/Roles/SYSMONITORROLE.htm
[4]: https://www.vertica.com/docs/9.2.x/HTML/Content/Authoring/SQLReferenceManual/Functions/VerticaFunctions/LicenseManagement/AUDIT.htm
[5]: https://www.vertica.com/docs/9.2.x/HTML/Content/Authoring/AdministratorsGuide/Licensing/MonitoringDatabaseSizeForLicenseCompliance.htm
[6]: https://github.com/DataDog/integrations-core/blob/master/vertica/datadog_checks/vertica/data/conf.yaml.example
[7]: https://docs.datadoghq.com/agent/guide/agent-commands/?tab=agentv6#start-stop-and-restart-the-agent
[8]: https://docs.datadoghq.com/agent/guide/agent-commands/?tab=agentv6#agent-status-and-information
[9]: https://github.com/DataDog/integrations-core/blob/master/vertica/metadata.csv
[10]: https://docs.datadoghq.com/help
