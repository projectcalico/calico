---
title: Install calicoctl
description: Install the CLI for Calico.
canonical_url: '/getting-started/clis/calicoctl/install'
---

## About installing calicoctl

`calicoctl` allows you to create, read, update, and delete {{site.prodname}} objects
from the command line. {{site.prodname}} objects are stored in one of two datastores,
either etcd or Kubernetes. The choice of datastore is determined at the time Calico
is installed. Typically for Kubernetes installations the Kubernetes datastore is the
default.

You can run `calicoctl` on any host with network access to the
{{site.prodname}} datastore as either a binary or a container.
For step-by-step instructions, refer to the section that
corresponds to your desired deployment.

<!--- Change download URL to latest release if user browsing master branch.  --->
{%- if page.version == "master" -%}
{% assign version = "latest/download" %}
{% else %}
{% assign version = "download/" | append: site.data.versions.first.components.calicoctl.version %}
{% endif %}

## Install calicoctl as a binary on a single host

{% tabs %}
<label:Linux,active:true>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -o calicoctl -O -L  "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl" 
   ```

1. Set the file to be executable.

   ```bash
   chmod +x calicoctl
   ```

   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}

%>
<label:Mac OSX>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -o calicoctl -O -L  "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl-darwin-amd64" 
   ```

1. Set the file to be executable.

   ```bash
   chmod +x calicoctl
   ```

   > **Note**: If you are faced with `cannot be opened because the developer cannot be verified` error when using `caicoctl` for the first time.
   > go to `Applicaitons > System Prefences > Security & Privacy` in the `General` tab at the bottom of the window click `Allow anyway`.
   >
   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}
%>
<label:Windows>
<%

1. Use the following powershell command to download the `calicoctl` binary.

   > **Tip**: Consider runing powershell as administraor and navigating 
   > to a location that's in your `PATH`. For example, `C:\Windows`.
   {: .alert .alert-success}

```
Invoke-WebRequest -Uri "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl-windows-amd64.exe" -OutFile "calicocttl.exe" 
```

%>
<label:Linux PPC64le>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -o calicoctl -O -L  "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl-linux-ppc64le" 
   ```

1. Set the file to be executable.

   ```bash
   chmod +x calicoctl
   ```

   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}
%>
<label:Linux arm64>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -o calicoctl -O -L  "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl-linux-arm64" 
   ```

1. Set the file to be executable.

   ```bash
   chmod +x calicoctl
   ```

   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}
%>
{% endtabs %}

## Install calicoctl as a kubectl plugin on a single host
{% tabs %}
<label:Linux,active:true>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -o kubectl-calico -O -L  "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl" 
   ```

1. Set the file to be executable.

   ```bash
   chmod +x kubectl-calico
   ```

   > **Note**: If the location of `kubectl-calico` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This is required in order for
   > kubectl to detect the plugin and allow you to use it.
   {: .alert .alert-info}

%>
<label:Mac OSX>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -o kubectl-calico -O -L  "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl-darwin-amd64" 
   ```

1. Set the file to be executable.

   ```bash
   chmod +x kubectl-calico
   ```

   > **Note**: If you are faced with `cannot be opened because the developer cannot be verified` error when using `caicoctl` for the first time.
   > go to `Applicaitons > System Prefences > Security & Privacy` in the `General` tab at the bottom of the window click `Allow anyway`.
   >
   > **Note**: If the location of `kubectl-calico` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This is required in order for
   > kubectl to detect the plugin and allow you to use it.
   {: .alert .alert-info}

%>
<label:Windows>
<%

1. Use the following powershell command to download the `calicoctl` binary.

   > **Tip**: Consider runing powershell as administraor and navigating 
   > to a location that's in your `PATH`. For example, `C:\Windows`.
   {: .alert .alert-success}

```
Invoke-WebRequest -Uri "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl-windows-amd64.exe" -OutFile "kubectl-calico.exe" 
```

%>
<label:Linux PPC64le>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -o kubectl-calico -O -L  "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl-linux-ppc64le" 
   ```

1. Set the file to be executable.

   ```bash
   chmod +x kubectl-calico
   ```

   > **Note**: If the location of `kubectl-calico` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This is required in order for
   > kubectl to detect the plugin and allow you to use it.
   {: .alert .alert-info}

%>
<label:Linux arm64>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -o kubectl-calico -O -L  "https://github.com/projectcalico/calicoctl/releases/{{ version }}/calicoctl-linux-arm64" 
   ```

1. Set the file to be executable.

   ```bash
   chmod +x kubectl-calico
   ```

   > **Note**: If the location of `kubectl-calico` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This is required in order for
   > kubectl to detect the plugin and allow you to use it.
   {: .alert .alert-info}

%>
{% endtabs %}

Verify the plugin works.

   ```
   kubectl calico -h
   ```

You can now run any `calicoctl` subcommands through `kubectl calico`.

> **Note**: If you run these commands from your local machine (instead of a host node), some of
> the node related subcommands will not work (like node status).
{: .alert .alert-info}

## Install calicoctl as a container on a single host

To install `calicoctl` as a container on a single host, log into the
target host and issue the following command.

```bash
docker pull {{page.registry}}{{page.imageNames["calicoctl"]}}:{{site.data.versions.first.title}}
```

## Install calicoctl as a Kubernetes pod


Use the YAML that matches your datastore type to deploy the `calicoctl` container to your nodes.
Determine datastore type using `kubectl exec -ti -n kube-system calicoctl -- calicoctl version` 
Cluster type of fdd indicates kubernetes api as a datastore.

- **etcd**

  ```bash
  kubectl apply -f {{ "/manifests/calicoctl-etcd.yaml" | absolute_url }}
  ```

  > **Note**: You can also
  > [view the YAML in a new tab]({{ "/manifests/calicoctl-etcd.yaml" | absolute_url }}){:target="_blank"}.
  {: .alert .alert-info}

- **Kubernetes API datastore**

  ```bash
  kubectl apply -f {{ "/manifests/calicoctl.yaml" | absolute_url }}
  ```

  > **Note**: You can also
  > [view the YAML in a new tab]({{ "/manifests/calicoctl.yaml" | absolute_url }}){:target="_blank"}.
  {: .alert .alert-info}

You can then run commands using kubectl as shown below.

```bash
kubectl exec -ti -n kube-system calicoctl -- /calicoctl get profiles -o wide
```

An example response follows.

```
NAME                 TAGS
kns.default          kns.default
kns.kube-system      kns.kube-system
```
{: .no-select-button}

We recommend setting an alias as follows.

```bash
alias calicoctl="kubectl exec -i -n kube-system calicoctl -- /calicoctl"
```

   > **Note**: In order to use the `calicoctl` alias
   > when reading manifests, redirect the file into stdin, for example:
   > ```bash
   > calicoctl create -f - < my_manifest.yaml
   > ```
   {: .alert .alert-info}

**Next step**:

[Configure `calicoctl` to connect to your datastore](configure).
