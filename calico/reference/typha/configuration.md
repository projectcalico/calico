---
title: Configuring Typha
description: Configure Typha for scaling Kubernetes API datastore (kdd).
canonical_url: '/reference/typha/configuration'
---

{% tabs %}
  <label:Operator,active:true>
<%

Typha configuration can not be modified when Calico is installed via the operator.

%>

  <label:Manifest>
<%

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
| `HealthPort`                      | `TYPHA_HEALTHPORT`                      | The port that Typha will serve health information over. [Default: `9098`] | int |
| `HealthHost`                      | `TYPHA_HEALTHHOST`                      | The address that Typha will bind its health endpoint to. [Default: `localhost`] | string |
| `LogFilePath`                     | `TYPHA_LOGFILEPATH`                     | The full path to the Typha log. Set to `none` to disable file logging. [Default: `/var/log/calico/typha.log`] | string |
| `LogSeverityFile`                 | `TYPHA_LOGSEVERITYFILE`                 | The log severity above which logs are sent to the log file. [Default: `Info`] | `Debug`, `Info`, `Warning`, `Error`, `Fatal` |
| `LogSeverityScreen`               | `TYPHA_LOGSEVERITYSCREEN`               | The log severity above which logs are sent to the stdout. [Default: `Info`] | `Debug`, `Info`, `Warning`, `Error`, `Fatal` |
| `LogSeveritySys`                  | `TYPHA_LOGSEVERITYSYS`                  | The log severity above which logs are sent to the syslog. Set to `""` for no logging to syslog. [Default: `Info`] | `Debug`, `Info`, `Warning`, `Error`, `Fatal` |
| `PrometheusGoMetricsEnabled`      | `TYPHA_PROMETHEUSGOMETRICSENABLED`      | Set to `false` to disable Go runtime metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. [Default: `true`]  | boolean |
| `PrometheusMetricsEnabled`        | `TYPHA_PROMETHEUSMETRICSENABLED`        | Set to `true` to enable the Prometheus metrics server in Typha. [Default: `false`] | boolean |
| `PrometheusMetricsHost`           | `TYPHA_PROMETHEUSMETRICSHOST`           | TCP network address that the Prometheus metrics server should bind to. [Default: `""`] | string |
| `PrometheusMetricsPort`           | `TYPHA_PROMETHEUSMETRICSPORT`           | TCP port that the Prometheus metrics server should bind to. [Default: `9091`] | int |
| `PrometheusProcessMetricsEnabled` | `TYPHA_PROMETHEUSPROCESSMETRICSENABLED` | Set to `false` to disable process metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. [Default: `true`] | boolean |

> **Note**: By default, if the health endpoint is enabled Typha listens on localhost.  However, if  Typha is used in
> Kubernetes, the kubelet will do health checks using the pod IP.  To work around this discrepancy, the Typha image
> supports a health-check CLI command that fetches the health endpoint:
> `calico-typha check (readiness|liveness) --port=<port>`.  If you modify the health port, you will need to add the
> `--port=<port>` argument to the liveness and readiness probe commands in the manifest.
{: .alert .alert-info}

#### etcd datastore configuration

| Configuration parameter | Environment variable  | Description | Schema |
| ----------------------- | --------------------- | ----------- | ------ |
| `EtcdCaFile`            | `TYPHA_ETCDCAFILE`    | Path to the file containing the root certificate of the certificate authority (CA) that issued the etcd server certificate. Configures Typha to trust the CA that signed the root certificate. The file may contain multiple root certificates, causing Typha to trust each of the CAs included. To disable authentication of the server by Typha, set the value to `none`. [Default: `/etc/ssl/certs/ca-certificates.crt`] | string |
| `EtcdCertFile`          | `TYPHA_ETCDCERTFILE`  | Path to the file containing the client certificate issued to Typha. Enables Typha to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/typha/cert.pem` (optional) | string |
| `EtcdEndpoints`         | `TYPHA_ETCDENDPOINTS` | Comma-delimited list of etcd endpoints to connect to. Example: `http://127.0.0.1:2379,http://127.0.0.2:2379`. | `<scheme>://<ip-or-fqdn>:<port>` |
| `EtcdKeyFile`           | `TYPHA_ETCDKEYFILE`   | Path to the file containing the private key matching the Typha client certificate. Enables Typha to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/typha/key.pem` (optional) | string |

#### Kubernetes API datastore configuration

The Kubernetes API datastore driver reads its configuration from Kubernetes-provided environment variables.

##### Environment variables

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| USE_POD_CIDR | Use the Kubernetes `Node.Spec.PodCIDR` field. This field is required when using the Kubernetes API datastore with host-local IPAM. [Default: false] | boolean |

#### Felix-Typha TLS configuration

| Configuration parameter | Environment variable   | Description | Schema |
| ----------------------- | ---------------------- | ----------- | ------ |
| `CAFile`                | `TYPHA_CAFILE`         | Path to the file containing the root certificate of the CA that issued the Felix client certificate. Configures Typha to trust the CA that signed the Felix client certificate. The file may contain multiple root certificates, causing Typha to trust each of the CAs included. Example: `/etc/typha/ca.pem` | string |
| `ClientCN`              | `TYPHA_CLIENTCN`       | If set, the `Common Name` that Felix's certificate must have. If you have enabled TLS on the communications from Felix to Typha, you must set a value here or in `ClientURISAN`. You can set values in both, as well, such as to facilitate a migration from using one to the other. If either matches, the communication succeeds. [Default: none] | string |
| `ClientURISAN`          | `TYPHA_CLIENTURISAN`   | If set, a URI SAN that Felix's certificate must have. We recommend populating this with a [SPIFFE](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md#2-spiffe-identity){:target="_blank"} string that identifies Felix. All Felix instances should use the same SPIFFE ID. If you have enabled TLS on the communications from Felix to Typha, you must set a value here or in `ClientCN`. You can set values in both, as well, such as to facilitate a migration from using one to the other. If either matches, the communication succeeds. [Default: none] | string |
| `ServerCertFile`        | `TYPHA_SERVERCERTFILE` |  Path to the file containing the server certificate issued to Typha. Typha presents this to Felix clients during the TLS handshake. Example: `/etc/typha/cert.pem` | string |
| `ServerKeyFile`         | `TYPHA_SERVERKEYFILE`  | Path to the file containing the private key matching the Typha server certificate. Example: `/etc/typha/key.pem` (optional) | string |

For more information on how to use and set these variables, refer to
[Connections from Felix to Typha (Kubernetes)](../../security/comms/crypto-auth#connections-from-felix-to-typha-kubernetes).

%>
{% endtabs %}
