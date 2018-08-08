# Udsuspver: Unix Domain Socket Unique Socket Pair Verify
This repos creates a Kubernetes [FlexVolume Driver](https://github.com/kubernetes/community/blob/release-1.6/contributors/devel/flexvolume.md) type `nodeagent/uds` to enable [Nodeagent](https://docs.google.com/document/d/1J67aol2phtZdBwbfuyk36fqLzRHn8c7k_2rAxwGslCk/edit#heading=h.x9snb54sjlu9) to verify the identity of a workload.
A Flexvolume driver type `nodeagent/uds` is added to each workload and when such a workload is created, with the volume type mounted, the Nodeagent is notified by the Flexvolume driver. The `workloadhandler` creates a Unix Domain Socket (UDS) per workload and then initializes the workloadAPI Grpc Server (see below). The workloadAPI Grpc server can get the credentials of the workload from the workload handler.

The code here was tested with Kubernetes version v1.8.

# What is in this repo
 ## Flexvolume driver:
 This is the flex volume driver that should be copied to /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds/uds
 Or you can use the provided initcontainer that copies the binary to the specified location on the node.
 See `nodeagent/nodeagent.yaml`
 
 ## WorkloadHandler:
 Workload handler creates a per workload unix domain listner socket. You can run any type of GRPC server on top of this. A sample `workloadapi` is provided here to show how to implement a Grpc server using the workloadhandler.
 The workload handler supports the [Grpc TransportCredentials interface](https://godoc.org/google.golang.org/grpc/credentials). This may be used by the `workloadapi` to get the verified attributes of the workload.
 
 ## WorkloadAPI:
 The workloadapi here is just a sample Grpc server. You will implement your own workload api. Perhaps [SPIFFE](https://spiffe.io/spiffe/)
 The workloadapi here shows how the `workloadhandler` credential can be extracted from the context when the workloadAPI is called.
 ```go
creds, e := wlh.CallerFromContext(ctx)
```

 ## Node Agent:
The workload API is going to be part of the nodeagent. The nodeagent shown here is also just a sample. It is here mainly to show how to initliaze the workloadapi and workloadhandler.
 ```go
 import (
 	...
 
 	nam "github.com/projectcalico/pod2daemon/nodeagentmgmt"
 	wlh "github.com/projectcalico/pod2daemon/workloadhandler"
 	mwi "github.com/projectcalico/pod2daemon/mgmtwlhintf"
 	wlapi "github.com/projectcalico/pod2daemon/workloadapi"
)

	// initialize the workload api.
	wl := wlapi.NewWlAPIServer()
	// initialize the workload api handler with the workload api.
	wli := mwi.NewWlHandler(wl, wlh.NewServer)
	// finally initialize the node mgmt interface with workload handler.
	mgmtServer := nam.NewServer(CfgWldApiUdsHome, wli)

```

# How to build
## GRPC protobuf used by FlexVolume Driver and WorkloadAPI
`./scripts/build-protobuf.sh`

Note: Unless you are changing the Grpc interface for FlexVolume driver you will not need to do this.

## FlexVolume Binary and Docker Image
`./scripts/build-docker.sh -i flexvol -c -i latest`

To just build the binary
`bazel build //flexvol:flexvol`

## NodeAgent Binary and Docker Image
`./scripts/build-docker.sh -c -i latest`

To just build the Nodeagent binary

`bazel build //nodeagent:nodeagent`

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

# How to setup the Node
## Kubeadm
1. Kubelet on each node must be started with the option --enable-controller-attach-detach=false.

## GCE/GKE

## AWS