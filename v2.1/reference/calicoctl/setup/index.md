---
title: Calicoctl Configuration Overview 
canonical_url: 'https://docs.projectcalico.org/v3.4/usage/calicoctl/configure/'
---

The `calicoctl` command line tool needs to be configured with details of
your datastore so that it can manage system configuration and
resources.

Configuration may be specified either using a YAML or JSON input file, or through
environment variables.  Configuration is determined as follows:

-  if a configuration file is present, the file is read and that configuration
   is used, otherwise
-  if the environment variables are set, those are used, otherwise
-  a default etcdv2 endpoint at http://127.0.0.1:2379 is assumed.

Calico currently supports the following datastores:

- [etcdv2](etcdv2) (default, recommended) 
- [Kubernetes API](kubernetes) (experimental) 

Calico supports, but does not require:

-  role based authentication using username and password
-  certificate and key authentication.


## Configuring datastore access

For detailed information on configuring calicoctl, see the documentation for your chosen
datastore.

- [etcdv2](etcdv2) (default, recommended) 
- [Kubernetes API](kubernetes) (experimental) 

