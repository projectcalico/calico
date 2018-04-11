---
title: Configuring Typha
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/typha/configuration'
---

Configuration for Typha is read from one of two possible locations, in
order, as follows.

1.  Environment variables, prefixed with `TYPHA_`.

2.  The Typha configuration file.  The path to this file defaults to
    `/etc/calico/typha.cfg` but can be overridden using the `-c` or
    `--config-file` options on the command line.

The value of any configuration parameter is the value read from the
*first* location containing a value. For example, if an environment variable
contains a value, it takes precedence.

If not set in any of these locations, most configuration parameters have
defaults, and it should be rare to have to explicitly set them.

The full list of parameters which can be set is as follows.

#### General configuration

| Configuration parameter           | Environment variable                    | Description  | Schema |
| --------------------------------- | --------------------------------------- | -------------| ------ |
| `DatastoreType`                   | `TYPHA_DATASTORETYPE`                   | The datastore that Typha should read endpoints and policy information from. [Default: `etcdv3`] | `etcdv3`, `kubernetes`|
| `HealthEnabled`                   | `TYPHA_HEALTHENABLED`                   | When enabled, exposes Typha health information via an http endpoint. | boolean |
| `LogFilePath`                     | `TYPHA_LOGFILEPATH`                     | The full path to the Typha log. Set to `none` to disable file logging. [Default: `/var/log/calico/typha.log`] | string |
| `LogSeverityFile`                 | `TYPHA_LOGSEVERITYFILE`                 | The log severity above which logs are sent to the log file. [Default: `Info`] | `Debug`, `Info`, `Warning`, `Error`, `Fatal` |
| `LogSeverityScreen`               | `TYPHA_LOGSEVERITYSCREEN`               | The log severity above which logs are sent to the stdout. [Default: `Info`] | `Debug`, `Info`, `Warning`, `Error`, `Fatal` |
| `LogSeveritySys`                  | `TYPHA_LOGSEVERITYSYS`                  | The log severity above which logs are sent to the syslog. Set to `""` for no logging to syslog. [Default: `Info`] | `Debug`, `Info`, `Warning`, `Error`, `Fatal` |
| `PrometheusGoMetricsEnabled`      | `TYPHA_PROMETHEUSGOMETRICSENABLED`      | Set to `false` to disable Go runtime metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. [Default: `true`]  | boolean |
| `PrometheusMetricsEnabled`        | `TYPHA_PROMETHEUSMETRICSENABLED`        | Set to `true` to enable the Prometheus metrics server in Typha. [Default: `false`] | boolean |
| `PrometheusMetricsPort`           | `TYPHA_PROMETHEUSMETRICSPORT`           | Experimental: TCP port that the Prometheus metrics server should bind to. [Default: `9091`] | int |
| `PrometheusProcessMetricsEnabled` | `TYPHA_PROMETHEUSPROCESSMETRICSENABLED` | Set to `false` to disable process metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. [Default: `true`] | boolean |

#### etcdv3 datastore configuration

| Configuration parameter | Environment variable  | Description | Schema |
| ----------------------- | --------------------- | ----------- | ------ |
| `EtcdCaFile`            | `TYPHA_ETCDCAFILE`    | The full path to the etcd Certificate Authority certificate file. To disable authentication of the server by Typha, set the value to `none`. [Default: `/etc/ssl/certs/ca-certificates.crt`] | string |
| `EtcdCertFile`          | `TYPHA_ETCDCERTFILE`  | The full path to the etcd certificate file. | string |
| `EtcdEndpoints`         | `TYPHA_ETCDENDPOINTS` | Comma-delimited list of etcd endpoints to connect to. Example: `http://etcd1:2379,http://etcd2:2379`. | `<scheme>://<ip-or-fqdn>:<port>` |
| `EtcdKeyFile`           | `TYPHA_ETCDKEYFILE`   | The full path to the etcd private key file. | string |

#### Kubernetes API datastore configuration

The Kubernetes API datastore driver reads its configuration from Kubernetes-provided environment variables.

#### Felix-Typha TLS configuration

{% include {{page.version}}/felix-typha-tls-intro.md %}

To use TLS, each Typha instance must have a certificate and key pair signed by
a trusted CA.  Typha then only accepts TLS connections, and requires each
connecting client to present a certificate that is signed by a trusted CA and
has an expected identity in its Common Name or URI SAN field.  Either
`ClientCN` or `ClientURISAN` must be configured, and Typha will check the
presented certificate accordingly.

-  For a [SPIFFE](https://github.com/spiffe/spiffe)-compliant deployment you
   should configure `ClientURISAN` with a [SPIFFE
   Identity](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md#2-spiffe-identity)
   and provision client certificates with the same identity in their URI SAN
   field.

-  Alternatively you can configure `ClientCN` and provision client certificates
   with that `ClientCN` value in their Common Name field.

If both those parameters are set, a client certificate only has to match one of
them; this is intended for when a deployment is migrating from using Common
Name to using a URI SAN, to express identity.

| Configuration parameter | Environment variable   | Description | Schema |
| ----------------------- | ---------------------- | ----------- | ------ |
| `CAFile`                | `TYPHA_CAFILE`         | The full path to the certificate file for the Certificate Authorities that Typha trusts for Felix-Typha communications. | string |
| `ClientCN`              | `TYPHA_CLIENTCN`       | If set, the Common Name that each connecting client certificate must have. [Default: not set] | string |
| `ClientURISAN`          | `TYPHA_CLIENTURISAN`   | If set, a URI SAN that each connecting client certificate must have. [Default: not set] | string |
| `ServerCertFile`        | `TYPHA_SERVERCERTFILE` | The full path to the certificate file for this Typha instance. | string |
| `ServerKeyFile`         | `TYPHA_SERVERKEYFILE`  | The full path to the private key file for this Typha instance. | string |

{% include {{page.version}}/felix-typha-tls-howto.md %}
