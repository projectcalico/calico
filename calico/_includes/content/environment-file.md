{%- if include.target == "felix" -%}
{%- assign etcd_endpoints = "FELIX_ETCDENDPOINTS" -%}
{%- assign etcd_cert_file = "FELIX_ETCDCERTFILE" -%}
{%- assign etcd_key_file = "FELIX_ETCDKEYFILE" -%}
{%- assign etcd_ca_file = "FELIX_ETCDCAFILE" -%}
{%- assign datastore_type = "FELIX_DATASTORETYPE" -%}
{%- else -%}
{%- assign etcd_endpoints = "ETCD_ENDPOINTS" -%}
{%- assign etcd_cert_file = "ETCD_CERT_FILE" -%}
{%- assign etcd_key_file = "ETCD_KEY_FILE" -%}
{%- assign etcd_ca_file = "ETCD_CA_CERT_FILE" -%}
{%- assign datastore_type = "DATASTORE_TYPE" -%}
{%- endif -%}

Use the following guidelines and sample file to define the environment variables for starting Calico on the host. For more help, see the 
{%- if include.install == "container" %}
 [{{site.nodecontainer}} configuration reference]({{site.baseurl}}/reference/node/configuration).
{% else %}
 [Felix configuration reference]({{site.baseurl}}/reference/felix/configuration).
{% endif %}

{% tabs %}
  <label: Kubernetes datastore,active:true>
  <%

For a Kubernetes datastore (default) set the following:

| Variable | Configuration guidance |
|----------|------------------------|
| {{datastore_type}} | Set to `kubernetes` |
| KUBECONFIG | Path to kubeconfig file to access the Kubernetes API Server |

{% if include.install == "container" %}
> **Note**: You will need to volume mount the kubeconfig file into the container at the location specified by the paths mentioned above.
{: .alert .alert-info}
{% endif %}

%>
  <label: etcd datastore>
  <%

For an etcdv3 datastore set the following:

| Variable | Configuration guidance |
|----------|------------------------|
| {{datastore_type}} | Set to `etcdv3` |
| {{etcd_endpoints}} | Comma separated list of etcdv3 cluster URLs, e.g. https://calico-datastore.example.com:2379 |
| {{etcd_ca_file}} | Path to CA certificate to validate etcd's server cert.  Required if using TLS and not using a public CA. |
| {{etcd_cert_file}}<br>{{etcd_key_file}} | Paths to certificate and keys used for client authentication to the etcd cluster, if enabled.   |

{% if include.install == "container" %}
> **Note**: If using certificates and keys, you will need to volume mount them into the container at the location specified by the paths mentioned above.
{: .alert .alert-info}
{% endif %}

%>
  <label: Either datastore>
  <%
  
For either datastore set the following:

| Variable | Configuration guidance |
|----------|------------------------|
| CALICO_NODENAME | Identifies the node. If a value is not specified, the compute server hostname is used to identify the Calico node. |
| CALICO_IP or CALICO_IP6 | If values are not specified for both, {{site.prodname}} uses the currently-configured values for the next hop IP addresses for this node—these can be configured through the Node resource. If no next hop addresses are configured, {{site.prodname}} automatically determines an IPv4 next hop address by querying the host interfaces (and configures this value in the Node resource). You can set CALICO_IP to `autodetect` for force auto-detection of IP address every time the node starts. If you set IP addresses through these environment variables, it reconfigures any values currently set through the Node resource. |
| CALICO_AS | If not specified, {{site.prodname}} uses the currently configured value for the AS Number for the node BGP client—this can be configured through the Node resource. If the Node resource value is not set, Calico inherits the AS Number from the global default value. If you set a value through this environment variable, it reconfigures any value currently set through the Node resource. |
| NO_DEFAULT_POOLS | Set to true to prevent {{site.prodname}} from creating a default pool if one does not exist. Pools are used for workload endpoints and not required for non-cluster hosts. |
| CALICO_NETWORKING_BACKEND | The networking backend to use. In `bird` mode, Calico will provide BGP networking using the BIRD BGP daemon; VXLAN networking can also be used. In `vxlan` mode, only VXLAN networking is provided; BIRD and BGP are disabled. If you want to run Calico for policy only, set to `none`. |

Sample `EnvironmentFile` - save to `/etc/calico/calico.env`

```shell
{{datastore_type}}=etcdv3
{{etcd_endpoints}}=https://calico-datastore.example.com:2379
{{etcd_ca_file}}="/pki/ca.pem"
{{etcd_cert_file}}="/pki/client-cert.pem"
{{etcd_key_file}}="/pki/client-key.pem"
{%- if include.install == "container" %}
CALICO_NODENAME=""
NO_DEFAULT_POOLS="true"
CALICO_IP=""
CALICO_IP6=""
CALICO_AS=""
CALICO_NETWORKING_BACKEND=bird
{%- endif %}
```
%>

  {% endtabs %}