---
title: etcd
---

- Calico uses etcd
- It's optimized

- Run anywhere accessible from everywhere

- There's plenty of ways to install etcd, we'll cover the easiest:

### Dockerized

```
docker run -p 2379:2379 quay.io/coreos/etcd \
--advertise-client-urls "http://localhost:2379,http://<ip>:2379" \
--listen-client-urls "http://localhost:2379,http://<ip>:2379"
```

Replacing `<ip>` with the IP address or hostname you want etcd to bind to.

Check it's running:

```
$ curl 127.0.0.1:2379/version
{"etcdserver":"2.3.7","etcdcluster":"2.3.0"}%
```

### Package

1. Install etcd using your favorite package manager. In most distro's it is hosted
as `etcd`.

2. Find and open the etcd environment file for editing.

3. Uncomment and set `ETCD_ADVERTISE_CLIENT_URLS` to
   `http://localhost:2379,http://<ip>:2379`

   Replacing `<ip>` with the externally accessible IP or hostname you want etcd
   to bind to.

4. Uncomment and set `ETCD_LISTEN_CLIENT_URLS` to
   `http://localhost:2379,http://<ip>:2379`

   Replacing `<ip>` with the externally accessible IP or hostname you want etcd
   to bind to.

3. Restart etcd to pick up the new changes.

4. Check it's running:

   ```
   $ curl 127.0.0.1:2379/version
   {"etcdserver":"2.3.7","etcdcluster":"2.3.0"}%
   ```
