# Deploying the guestbook application
The following steps describe how to deploy the Kubernetes [guestbook application][guestbook].

This guide assumes you have a Kubernetes cluster as configured by the [Vagrant CoreOS guide](../VagrantCoreOS.md)

1) Log on to the master node.
```
vagrant ssh calico-01
```

2) Create the guestbook application pods and services using the provided manifest.
```
kubectl create -f guestbook.yaml
```

3) Check that the redis-master, redis-slave, and frontend pods are running correctly.  After a few minutes, the following command should show all pods in `Running` state.
```
kubectl get pods
```
> Note: The guestbook demo relies on a number of docker images which may take up to 5 minutes to download.

4) Check that Calico endpoints have been created for the guestbook pods.
```
calicoctl endpoint show --detailed
```

5) The above manifests configure a web appliation that is exposed on port 30001 on each of your nodes using the Kubernetes NodePort mechanism. 
```
kubectl describe svc frontend
```
The service is available internally via a `10.100.0.X` IP address on port `80`, and outside the cluster using the NodePort `30001`.

To access the guestbook application frontend, visit `http://172.18.18.101:30001` in your favorite browser.  Because we used a NodePort service to expose it outside the cluster, it should also be available at `http://172.18.18.102:30001`.


[guestbook]: https://github.com/kubernetes/kubernetes/blob/master/examples/guestbook/README.md


[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/kubernetes/vagrant-coreos/guestbook.md?pixel)](https://github.com/igrigorik/ga-beacon)
