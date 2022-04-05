---
title: Enforce Calico network policy using Istio (tutorial)
description: Learn how Calico integrates with Istio to provide fine-grained access control using Calico network policies enforced within the service mesh and network layer.
canonical_url: '/security/tutorials/app-layer-policy/enforce-policy-istio'
---

This tutorial sets up a microservices application, then demonstrates how to use {{site.prodname}} application layer policy to mitigate some common threats.

> **Note**: This tutorial was verified using Istio v1.10.2. Some content may not apply to the latest Istio version.
{: .alert .alert-info}

## Prerequisites

1. Build a Kubernetes cluster.
2. Install {{site.prodname}} on Kubernetes:
  - If {{site.prodname}} is not installed on Kubernetes, see [Calico on Kubernetes]({{ site.baseurl }}/getting-started/kubernetes/quickstart).
  - If {{site.prodname}} is already installed on Kubernetes, verify that [Calico networking]({{ site.baseurl }}/networking/) (or a non-Calico CNI) and {{site.prodname}} network policy are installed.
3. Install the [calicoctl command line tool]({{ site.baseurl }}/maintenance/clis/calicoctl/install).
  **Note**: Ensure calicoctl is configured to connect with your datastore.
4. [Enable application layer policy]({{site.baseurl}}/security/app-layer-policy).
  **Note**: Label the default namespace for the Istio sidecar injection (`istio-injection=enabled`).
  `kubectl label namespace default istio-injection=enabled`

### Install the demo application

We will use a simple microservice application to demonstrate {{site.prodname}}
application layer policy.  The {% include open-new-window.html text='YAO Bank'
url='https://github.com/projectcalico/yaobank' %} application creates a
customer-facing web application, a microservice that serves up account
summaries, and an {% include open-new-window.html text='etcd'
url='https://github.com/coreos/etcd' %} datastore.

```bash
kubectl apply -f {{ "/security/tutorials/app-layer-policy/manifests/10-yaobank.yaml" | absolute_url }}
```

> **Note**: You can also
> [view the manifest in your browser](manifests/10-yaobank.yaml){:target="_blank"}.
{: .alert .alert-info}

Verify that the application pods have been created and are ready.

    kubectl get pods

When the demo application has come up, you will see three pods.

```
NAME                        READY     STATUS    RESTARTS   AGE
customer-2809159614-qqfnx   3/3       Running   0          21h
database-1601951801-m4w70   3/3       Running   0          21h
summary-2817688950-g1b3n    3/3       Running   0          21h
```
{: .no-select-button}

### Determining ingress IP and port

You will use the `istio-ingressgateway` service to access the YAO Bank
application. Determine your ingress host and port {% include
open-new-window.html text='following the Istio instructions'
url='https://istio.io/docs/tasks/traffic-management/ingress/ingress-control/#determining-the-ingress-ip-and-ports'
%}. Once you have the `INGRESS_HOST` and `INGRESS_PORT` variables set, you can
set the `GATEWAY_URL` as follows.

```bash
export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT
```

Point your browser to `http://$GATEWAY_URL/` to confirm the YAO Bank application is functioning
correctly.  It may take several minutes for all the services to come up and respond, during which
time you may see 404 or 500 errors.

### The need for policy

Although {{site.prodname}} & Istio are running in the cluster, we have not defined any authentication
policy. Istio was configured to mutually authenticate traffic between the pods in your application,
so only connections with Istio-issued certificates are allowed, and all inter-pod traffic is encrypted with TLS.  That's already a big step in the right direction.

But, let's consider some deficiencies in this security architecture:

 * All incoming connections from workloads in the Istio mesh are equally trusted
 * Possession of a key & certificate pair is the *only* access credential considered.

To understand why these might be a problem, let's take them one at a time.

#### Trusting workloads

Trusting connections from any workload in the Istio mesh is a poor security architecture because,
like Kubernetes, Istio is designed to host multiple applications.  Some of those applications may
not be as trusted as others.  They may be operated by different users or teams with wildly different
security requirements.  We don't want our secure financial application microservices accessible from
some hacky prototype another developer is cooking up.

Even within our own application, the best practice is to limit access as much
as possible.  Only pods that need access to a service should get it.  Consider
the YAO Bank application.  The customer web service does not need, and should
not have direct access to the backend database.  The customer web service needs
to directly interact with clients outside the cluster, some of whom may be
malicious.  Unfortunately, vulnerabilities in web applications are all too
common.  For example, an {% include open-new-window.html text='unpatched
vulnerability in Apache Struts'
url='https://nvd.nist.gov/vuln/detail/CVE-2017-5638' %} is what allowed
attackers their initial access into the Equifax network where they then
launched a devastating attack to steal millions of people's financial
information.

Imagine what would happen if an attacker were to gain control of the customer web pod in our
application. Let's simulate this by executing a remote shell inside that pod.

    kubectl exec -ti customer-<fill in pod ID> -c customer -- bash

Notice that from here, we get direct access to the backend database.  For example, we can list all the entries in the database like this:

    curl http://database:2379/v2/keys?recursive=true | python -m json.tool

(Piping to `python -m json.tool` nicely formats the output.)

#### Single-factor authentication

The possession of a key and certificate pair is a very strong assertion that a
connection is authentic because it is based on cryptographic proofs that are
believed to be nearly impossible to forge.  When we authenticate connections
this way we can say with extremely high confidence that the party on the other
end is in possession of the corresponding key. However, this is only a proxy
for what we actually want to be confident of: that the party on the other end
really is the authorized workload we want to communicate with.  Keeping the
private key a secret is vital to this confidence, and occasionally attackers
can find ways to trick applications into giving up secrets they should not.
For example, the {% include open-new-window.html text='Heartbleed'
url='http://heartbleed.com' %} vulnerability in OpenSSL allowed attackers to
trick an affected application into reading out portions of its memory,
compromising private keys.

#### Network policy

We can mitigate both of the above deficiencies with a {{site.prodname}} policy.

    wget {{ "/security/tutorials/app-layer-policy/manifests/30-policy.yaml" | absolute_url }}
    calicoctl create -f 30-policy.yaml

> **Note**: You can also
> [view the manifest in your browser](manifests/30-policy.yaml){:target="_blank"}.
{: .alert .alert-info}

Let's examine this policy piece by piece.  It consists of three policy objects, one for each
microservice.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: customer
spec:
  selector: app == 'customer'
  ingress:
   - action: Allow
     http:
       methods: ["GET"]
  egress:
    - action: Allow
```
{: .no-select-button}

This policy protects the customer web app.  Since this application is customer facing, we do not
restrict what can communicate with it.  We do, however, restrict its communications to HTTP `GET`
requests.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: summary
spec:
  selector: app == 'summary'
  ingress:
    - action: Allow
      source:
        serviceAccounts:
          names: ["customer"]
  egress:
    - action: Allow
```
{: .no-select-button}

The second policy protects the account summary microservice.  We know the only consumer of this
service is the customer web app, so we restrict the source of incoming connections to the service
account for the customer web app.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: database
spec:
  selector: app == 'database'
    ingress:
      - action: Allow
        source:
          serviceAccounts:
            names: ["summary"]
    egress:
      - action: Allow
```
{: .no-select-button}

The third policy protects the database.  Only the summary microservice should have direct access to
the database.

Let's verify our policy is working as intended.  First, return to your browser and refresh to
ensure policy enforcement has not broken the application.

Next, return to the customer web app.  Recall that we simulated an attacker gaining control of that
pod by executing a remote shell inside it.

    kubectl exec -ti customer-<fill in pod ID> -c customer bash

Repeat our attempt to access the database.

    curl -I http://database:2379/v2/keys?recursive=true

We have left out the JSON formatting because we do not expect to get a valid JSON response. This
time we should get a `403 Forbidden` response.  Only the account summary microservice has database
access according to our policy.
