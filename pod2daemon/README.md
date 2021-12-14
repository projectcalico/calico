# pod2daemon
pod2daemon enables secure communication between a Kubernetes pod and a daemon (e.g. created with a DaemonSet) running on the host. It creates a Kubernetes [FlexVolume Driver](https://github.com/kubernetes/community/blob/release-1.6/contributors/devel/flexvolume.md) type `nodeagent/uds` to enable [Nodeagent](https://docs.google.com/document/d/1J67aol2phtZdBwbfuyk36fqLzRHn8c7k_2rAxwGslCk/edit#heading=h.x9snb54sjlu9) to verify the identity of a workload.
A Flexvolume driver type `nodeagent/uds` is added to each workload and when such a workload is created, with the volume type mounted, the Nodeagent is notified by the Flexvolume driver. The `workloadhandler` creates a Unix Domain Socket (UDS) per workload and then initializes the workloadAPI Grpc Server (see below). The workloadAPI Grpc server can get the credentials of the workload from the workload handler.

The code here was tested with Kubernetes version v1.8.

# What is in this repo
 ## Flexvolume driver:
 This is the flex volume driver that should be copied to /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds/uds
 Or you can use the provided initcontainer that copies the binary to the specified location on the node.
 See `nodeagent/nodeagent.yaml`
 
# How to build

## FlexVolume Binary

    make build

Outputs to `bin/flexvol-<arch>`

## Docker image

    make image

# How to setup the FlexVolume driver
See `nodeagent/nodeagent.yaml` initContainer to see how the FlexVolume driver is setup.

The `nodeagent.yaml` also shows how the nodeagent volumes need to be setup.

# How to setup the Workload
See `flexvol/udsver-mount.yaml` for a sample of how a workload will setup the flexvolume.
```yaml
...snip
     containers:
        volumeMounts:
        - mountPath: /tmp/udsver
          name: test-volume
      volumes:
        - name: test-volume
          flexVolume:
            driver: nodeagent/uds
```
