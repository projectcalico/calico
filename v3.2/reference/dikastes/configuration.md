---
title: Configuring Dikastes
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/dikastes/configuration'
---

Configuration for Dikastes is read from the command line arguments passed. The command line options
are listed in the following table.

| Option            | Short Option | Description  | Schema |
|-------------------|--------------|--------------|--------|
| `--listen <path>` | `-l`         | Unix domain socket path for Dikastes to create its listen socket. This socket accepts connections from Envoy to query whether a request should be authorized. | string |
| `--dial <path>`   | `-d`         | Unix domain socket path where Dikastes should connect to the Policy Sync API (provided by Felix) to obtain the policy for the pod it is enforcing on. | string |
| `--debug`         |              | Flag to set Dikastes to log extra information for debugging purposes | n/a |

For example:

	dikastes server -l /var/run/dikastes/socket -d /var/run/felix/nodeagent/socket --debug
