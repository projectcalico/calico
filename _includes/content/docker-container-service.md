This section describes how to run `{{site.nodecontainer}}` as a Docker container.

> **Note**: We include examples for systemd, but the commands can be
> applied to other init daemons such as upstart.
{: .alert .alert-info}

#### Step 1: Create environment file

{% include content/environment-file.md install="container" target="calico/node" %}

#### Step 2: Configure the init system

Use an init daemon (like systemd or upstart) to start the the {{site.nodecontainer}} image as a service using the EnvironmentFile values.

Sample systemd service file: `{{site.noderunning}}.service`

```shell
[Unit]
Description={{site.noderunning}}
After=docker.service
Requires=docker.service

[Service]
EnvironmentFile=/etc/calico/calico.env
ExecStartPre=-/usr/bin/docker rm -f {{site.noderunning}}
ExecStart=/usr/bin/docker run --net=host --privileged \
 --name={{site.noderunning}} \
 -e NODENAME=${CALICO_NODENAME} \
 -e IP=${CALICO_IP} \
 -e IP6=${CALICO_IP6} \
 -e CALICO_NETWORKING_BACKEND=${CALICO_NETWORKING_BACKEND} \
 -e AS=${CALICO_AS} \
 -e NO_DEFAULT_POOLS=${NO_DEFAULT_POOLS} \
 -e DATASTORE_TYPE=${DATASTORE_TYPE} \
 -e ETCD_ENDPOINTS=${ETCD_ENDPOINTS} \
 -e ETCD_CA_CERT_FILE=${ETCD_CA_CERT_FILE} \
 -e ETCD_CERT_FILE=${ETCD_CERT_FILE} \
 -e ETCD_KEY_FILE=${ETCD_KEY_FILE} \
 -e KUBECONFIG=${KUBECONFIG} \
 -v /var/log/calico:/var/log/calico \
 -v /var/lib/calico:/var/lib/calico \
 -v /var/run/calico:/var/run/calico \
 -v /run/docker/plugins:/run/docker/plugins \
 -v /lib/modules:/lib/modules \
 -v /etc/pki:/pki \
 {{page.registry}}{{page.imageNames["calico/node"]}}:{{site.data.versions.first.title}} /bin/calico-node -felix

ExecStop=-/usr/bin/docker stop {{site.noderunning}}

Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
```

Upon start, the systemd service:

  - Confirms Docker is installed under the `[Unit]` section
  - Gets environment variables from the environment file above
  - Removes existing `{{site.nodecontainer}}` container (if it exists)
  - Starts `{{site.nodecontainer}}`

The script also stops the `{{site.nodecontainer}}` container when the service is stopped.

> **Note**: Depending on how you've installed Docker, the name of the Docker service
> under the `[Unit]` section may be different (such as `docker-engine.service`).
> Be sure to check this before starting the service.
{: .alert .alert-info}
