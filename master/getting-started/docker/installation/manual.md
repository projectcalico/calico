---
title: Adding Calico to Docker
---

On each host, perform the following:

1. Download the calicoctl binary:

	 ```
   sudo wget -O /usr/local/bin/calicoctl http://www.projectcalico.org/builds/calicoctl
	 sudo chmod +x calicoctl
   ```

2. Launch `calico/node`:

   ```
   sudo calicoctl node run
   ```


Check that your installation was successful with the following command:

```
calicoctl node checksystem
```

## Next Steps

With `calico/node` installed and running, you are ready to follow our guide on
[creating networks, launching containers, and configuring policy]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/advanced-policy)
