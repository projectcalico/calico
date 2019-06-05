---
title: Application layer policy tutorial
canonical_url: 'https://docs.projectcalico.org/v3.7/security/app-layer-policy/index'
---

This tutorial sets up a microservices application, then demonstrates how to use Calico application layer policy to mitigate some common threats.

## Prerequisites

1. Install [Calico on a Kubernetes cluster]({{site.baseurl}}/{{page.version}}/getting-started/).

2. (Optional) Enable Calico network using [Kubernetes Data Store]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/calico#installing-with-the-kubernetes-api-datastore50-nodes-or-less) over etcd. 
  **Note**: You can also use an a non-Calico CNI for networking. 

3. Install [calicoctl command line tool]({{site.baseurl}}/{{page.version}}/getting-started/calicoctl/install). 
  **Note**: Ensure calicoctl is configured to connect with your datastore. 

4. Install [Istio and configure Calico]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/app-layer-policy)
  **Note**: Ensure that you create a default namespace for Istio sidecar injection: 
  `kubectl label namespace default istio-injection=enabled`

### Install the demo application

We will use a simple microservice application to demonstrate {{site.prodname}} application layer policy.  The [YAO Bank](https://github.com/spikecurtis/yaobank) application creates a customer-facing web application, a microservice that serves up account summaries, and an [etcd](https://github.com/coreos/etcd) datastore.

```bash
kubectl apply -f \
{{site.url}}/{{page.version}}/security/app-layer-policy/manifests/10-yaobank.yaml
```

> **Note**: You can also
> [view the manifest in your browser](manifests/10-yaobank.yaml){:target="_blank"}.
{: .alert .alert-info}


Verify that the application pods have been created and are ready.

    kubectl get pods

When the demo application has come up, you will see three pods.

```bash
NAME                        READY     STATUS    RESTARTS   AGE
customer-2809159614-qqfnx   3/3       Running   0          21h
database-1601951801-m4w70   3/3       Running   0          21h
summary-2817688950-g1b3n    3/3       Running   0          21h
```
{: .no-select-button}

View the Kubernetes ServiceAccounts created by the manifest.

    kubectl get serviceaccount

You should see a Kubernetes ServiceAccount for each microservice in the application (in addition to the `default` account).

```bash
NAME       SECRETS   AGE
customer   1         21h
database   1         21h
default    1         21h
summary    1         21h
```
{: .no-select-button}

Examine the Kubernetes Secrets.

    kubectl get secret

You should see output similar to the following.

```bash
NAME                   TYPE                                  DATA      AGE
customer-token-mgb8w   kubernetes.io/service-account-token   3         21h
database-token-nb5xp   kubernetes.io/service-account-token   3         21h
default-token-wwml6    kubernetes.io/service-account-token   3         21h
istio.customer         istio.io/key-and-cert                 3         21h
istio.database         istio.io/key-and-cert                 3         21h
istio.default          istio.io/key-and-cert                 3         21h
istio.summary          istio.io/key-and-cert                 3         21h
summary-token-8kpt1    kubernetes.io/service-account-token   3         21h
```
{: .no-select-button}

Notice that Istio CA will have created a secret of type `istio.io/key-and-cert` for each
service account.  These keys and X.509 certificates are used to cryptographically authenticate
traffic in the Istio service mesh, and the corresponding service account identities are used by
{{site.prodname}} in authorization policy.

### Determining ingress IP and port

You will use the `istio-ingressgateway` service to access the YAO Bank application.

1. If your Kubernetes cluster is running in an environment that supports external load balancers, the IP address of
   ingress can be  obtained by the following command:

   ```bash
   kubectl get svc istio-ingressgateway -n istio-system
   ```

   whose output should be similar to

   ```bash
   NAME                   TYPE           CLUSTER-IP       EXTERNAL-IP     PORT(S)                                      AGE
   istio-ingressgateway   LoadBalancer   172.21.109.129   130.211.10.121  80:31380/TCP,443:31390/TCP,31400:31400/TCP   17h
   ```
   {: .no-select-button}

   The address of the ingressgateway service is the external IP of the `istio-ingressgateway`, followed by port 80:

   ```bash
   export GATEWAY_URL=130.211.10.121:80
   ```

1. If your cluster does not support external load balancers, you can use the public IP of the worker
node, along with the NodePort, to access the ingress. The IP & port can be obtained from the output
of the following command:

   ```bash
   export GATEWAY_URL=$(kubectl get pod -n istio-system -l istio=ingressgateway -o \
   'jsonpath={.items[0].status.hostIP}'):$(kubectl get svc istio-ingressgateway -n istio-system -o \
   'jsonpath={.spec.ports[0].nodePort}')
   ```

Point your browser to `http://$GATEWAY_URL/` to confirm the YAO Bank application is functioning
correctly.  It may take several minutes for all the services to come up and respond, during which
time you may see 404 or 500 errors.

### The need for policy

Although {{site.prodname}} & Istio are running in the cluster, we have not defined any authorization
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

Even within our own application, the best practice is to limit access as much as possible.  Only
pods that need access to a service should get it.  Consider the YAO Bank application.  The customer
web service does not need, and should not have direct access to the backend database.  The customer
web service needs to directly interact with clients outside the cluster, some of whom may be
malicious.  Unfortunately, vulnerabilities in web applications are all too common.  For example, an
[unpatched vulnerability in Apache Struts][struts cve] is what allowed attackers their initial
access into the Equifax network where they then launched a devastating attack to steal millions of
people's financial information.

Imagine what would happen if an attacker were to gain control of the customer web pod in our
application. Let's simulate this by executing a remote shell inside that pod.

    kubectl exec -ti customer-<fill in pod ID> -c customer bash

Notice that from here, we get direct access to the backend database.  For example, we can list all the entries in the database like this:

    curl http://database:2379/v2/keys?recursive=true | python -m json.tool

(Piping to `python -m json.tool` nicely formats the output.)

#### Single-factor authentication

The possession of a key and certificate pair is a very strong assertion that a connection is
authentic because it is based on cryptographic proofs that are believed to be nearly impossible to
forge.  When we authenticate connections this way we can say with extremely high confidence that the
party on the other end is in possession of the corresponding key. However, this is only a proxy for
what we actually want to be confident of: that the party on the other end really is the authorized
workload we want to communicate with.  Keeping the private key a secret is vital to this confidence,
and occasionally attackers can find ways to trick applications into giving up secrets they should
not.  For example, the [Heartbleed] vulnerability in OpenSSL allowed attackers to trick an affected
application into reading out portions of its memory, compromising private keys.

Let's simulate an attacker who has stolen the private keys of another pod.  Since the keys are
stored as Kubernetes secrets, we won't exploit a vulnerability in a service, but instead just mount
the secret in a pod that will simulate an attacker.

If you still have your shell open in the customer pod, exit out or open a new terminal tab (we will
return to the customer pod later).

```bash
kubectl apply -f \
{{site.url}}/{{page.version}}/security/app-layer-policy/manifests/20-attack-pod.yaml
```

Take a look at the [`20-attack-pod.yaml` manifest in your browser](manifests/20-attack-pod.yaml).
It creates a pod and mounts `istio.summary` secret.  This will allow us to masquerade as if we were
the `summary` service, even though this pod is not run as that service account.  Let's try this out.  First, `exec` into the pod.

    kubectl exec -ti attack-<fill in pod ID> bash

Now, we will attack the database.  Instead of listing the contents like we did before, let's try
something more malicious, like changing the account balance with a `PUT` command.

    curl -k https://database:2379/v2/keys/accounts/519940/balance -d value="10000.00" \
    -XPUT --key /etc/certs/key.pem --cert /etc/certs/cert-chain.pem

Unlike when we did this with the customer web pod, we do not have Envoy to handle encryption, so we
have to pass an `https` URL, the `--key` and `--cert` parameters to `curl` to do the cryptography.

Return to your web browser and refresh to confirm the new balance.

#### Network policy

We can mitigate both of the above deficiencies with a {{site.prodname}} policy.

    wget {{site.url}}/{{page.version}}/security/app-layer-policy/manifests/30-policy.yaml
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

Finally, let's return to the attack pod that simulated stealing secret keys.

    kubectl exec -ti attack-<fill in pod ID> bash

Let's repeat our attack with stolen keys. We'll further increase the account balance to highlight
whether it succeeds.

```bash
curl -k --connect-timeout 3 https://database:2379/v2/keys/account/519940/balance -d \
value="99999.99" -XPUT --key /etc/certs/key.pem --cert /etc/certs/cert-chain.pem
```

You should get no response, and refreshing your browser should not show an increased balance.

You might wonder how {{site.prodname}} was able to detect and prevent this attack—the attacker was
able to steal the keys which prove identity in our system.  This highlights the value of multi-layer
authorization checks.  Although our attack pod had the keys to fool the X.509 certificate check,
{{site.prodname}} also monitors the Kubernetes API Server for which IP addresses are associated with which
service accounts.  Since our attack pod has an IP not associated with the account summary service
account we disallow the connection.

 [yao bank]: https://github.com/spikecurtis/yaobank
 [etcd]: https://github.com/coreos/etcd
 [struts cve]: https://nvd.nist.gov/vuln/detail/CVE-2017-5638
 [heartbleed]: http://heartbleed.com/
