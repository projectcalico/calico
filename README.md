[![Build Status](https://semaphoreci.com/api/v1/calico/libcalico-go/branches/master/shields_badge.svg)](https://semaphoreci.com/calico/libcalico-go) [![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org) [![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico) [![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/projectcalico/libcalico-go)

# libcalico-go
This repositiory contains Calico's Go components:

- `libcalico`, which can be imported as `"github.com/projectcalico/libcalico-go/lib"`

This library is used by: 
  - [calicoctl](https://github.com/projectcalico/calicoctl)
  - [Calico CNI plugin](https://github.com/projectcalico/calico-cni)
  - [Calico libnetwork plugin](https://github.com/projectcalico/libnetwork-plugin)
  - [felix](https://github.com/projectcalico/felix).
 
If you wish to use libcalico for integration with Calico networking and
policy, the main entry point to managing Calico configuration is through
the client.

-  Documentation for the client is in [lib/client GoDoc](https://godoc.org/github.com/projectcalico/libcalico-go/lib/client).
-  The resource structure definitions are defined in [lib/api](https://godoc.org/github.com/projectcalico/libcalico-go/lib/api), this
   includes detailed per-resource and per-field level descriptions.
-  Resource definitions can be found in [Calico docs](http://docs.projectcalico.org/master/reference/calicoctl/resources/)
-  This repository also includes the implementation for Calico IPAM which can be found in `lib/client` 

If you are developing against the code in libcalico, please run the tests before
submitting a Pull Request.

To run the tests locally (requires a full golang environment Go 1.7+):

    make ut
    
To run the tests within a containerized environment:

    make test-containerized
    
