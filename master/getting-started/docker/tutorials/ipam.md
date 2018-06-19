---
title: IPAM
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/tutorials/ipam'
---

With the release of Docker 1.10, support has been added to allow users to
select a specific IP address when creating a container.  In order to use
this feature, Docker requires that you specify the `--subnet` parameter when running
`docker network create`.

{{site.prodname}} requires that the passed `--subnet` value be the same CIDR as an existing
{{site.prodname}} IP pool.  

## Example

#### 1. Create a {{site.prodname}} IP pool

```
cat << EOF | calicoctl create -f -
- apiVersion: projectcalico.org/v3
  kind: IPPool
  metadata:
    name: ippool-1
  spec:
    cidr: 192.0.2.0/24
EOF
```

#### 2. Create a Docker network using the IP pool

```
docker network create --driver calico --ipam-driver calico-ipam --subnet=192.0.2.0/24 my_net
```

>Notice that our `--subnet` value is identical to our `cidr` above.

#### 3. Create a container using a specific IP address from the pool

```
docker run --net my_net --name my_workload --ip 192.0.2.100 -tid busybox
```

#### 4. Verify that the IP address was assigned to the container

```
docker inspect -f {%raw%}'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'{%endraw%} my_workload
```
