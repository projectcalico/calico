> ![warning](../images/warning.png) This document describes an alpha release of calicoctl
>
> The version of calico described in this document is an alpha release of
> calicoctl that provides management of resources using YAML and JSON
> file-based input.  The same set of commands are used for managing all 
> different resource types.
>
> This version of calicoctl does not yet contain any container-specific
> processing, this includes:
>
> -  Starting/stopping Calico node and the libnetwork plugin
> -  Management of Docker network profiles
> -  Container management commands to add/remove Calico networking from
>    and existing container.
>
> If you require any of those features, please use the latest version of
> calicoctl attached to the releases at [calico-containers](https://github.com/projectcalico/calico-containers/releases).
>
> If you are using Calico as a CNI driver, this version of calicoctl will
> allow you to manage all required Calico features, however you will need
> to start the Calico node image directly as a container.

# calicoctl user guide

This user guide describes the `calicoctl` command line tool used to manage Calico
configuration and policy.

This user guide contains a command reference, and more general sections
covering resource types, file formats and policy management.

Select one of the following links to get started.

-  [Setting up calicoctl](general/setup.md)
-  [The calicoctl command reference](calicoctl.md)
-  [Resources (valid types, file formats)](resources/README.md)
-  [Policy](general/policy.md)
-  [BGP configuration](general/bgp.md)

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
