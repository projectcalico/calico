[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)

# Calico API server

<blockquote>
Note that the documentation in this repo is targeted at Calico contributors.
<h1>Documentation for Calico users is here:<br><a href="http://docs.projectcalico.org">http://docs.projectcalico.org</a></h1>
</blockquote>

This repository contains the Project Calico API server for Kubernetes.

## Building the plugins and running tests

To build the code into a docker image:

```
make image
```

To run the tests:

```
make test
```

To update generated code:

```
make gen-files
```

## License

Calico binaries are licensed under the [Apache v2.0 license](LICENSE), with the exception of some [GPL licensed eBPF programs](https://github.com/projectcalico/felix/tree/master/bpf-gpl).
