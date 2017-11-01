# Udsuspver: Unix Domain Socket Unique Socket Pair Verify
This is a prototype to confirm that we can use Kubernetes [FlexVolume Driver](https://github.com/kubernetes/community/blob/release-1.6/contributors/devel/flexvolume.md). This prototype was tested with Kubernetes version v1.7.3.

# What is in this repo
 ## flexvolume driver: This is the flex volume driver that should be copied to /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds/uds
 ## nodeagent: A nodeagent that the above flex volume driver will notify of pods that mount a flexvolume of type nodeagent/uds. This nodeagent will then open a uds for such pods.

# How to setup the host/node to use with this prototype.
 1. Kubelet must be started with the option --enable-controller-attach-detach=false.
 1. You must also create the directories /tmp/nodeagent and /tmp/udsuspver/
/tmp/udsuspver is where the flex volume driver connects to Nodeagent over uds.
/tmp/nodeagent is where the unique uds per pod is hosted and mounted into each pod. 
