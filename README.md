# Application Layer Policy

This is a technical preview of Application Layer Policy for [Project Calico][calico], which enforces network and
application layer authorization policies using [Istio].

![arch](https://github.com/projectcalico/app-policy/raw/master/docs/arch.png)

Istio mints and distributes cryptographic identities and uses them to establish mutually authenticated TLS connections
between pods.  Calico enforces authorization policy on this communication integrating cryptographic identities and 
network layer attributes.

A small shim filter is inserted into the proxy, which calls out to Calico components when service requests are
processed.  We compute policy based on a global store which is distributed to the Calico components.
 
## Getting Started
 
This guide explains how to install Calico & Istio into your cluster, and use it to
enforce authorization policies in a simple demo application.
 
This demo will run on a Calico-enabled Kubernetes cluster. You will need a [Kubernetes][kubernetes] cluster running v1.8 or later
with RBAC and [Initializers] enabled. 
 
If you have Calico or Istio installed, remove them from the cluster.  This preview relies on the latest Calico build and
several [custom-built Istio components](https://github.com/projectcalico/istio/tree/dikastes) which will be installed in
the demo.

### Starting a cluster with Vagrant

If you do not have a test cluster running Kubernetes 1.8 or later with RBAC and Initializers, this section will walk you through
creating one on your local machine using [Vagrant].

If you already have a test cluster, you can skip to [installing Calico](#install-calico).

#### Prerequisites

 - [Vagrant]
 - [VirtualBox]

Install Vagrant and VirtualBox, then from the root directory of this repo:

    cd config/cluster
    vagrant up
    
This will create a 3-node Kubernetes cluster in 3 VirtualBox VMs.

**DO NOT USE THIS IN PRODUCTION**.  The API server is loaded with a certificate and keypair checked into this
repository.  If you put this in production anyone will be able to impersonate your API server. 

Open VirtualBox and click on one of the created VMs, then click Network and go to the tab for Adapter 2.  You should see
it "Attached to: Host-only Adapter".  Make a note of the entry in the "Name:" box.  This is the name of the host-only
network adapter you will use to communicate with your cluster.

Add an IP address to this network adapter and bring it up.

On Linux:

    sudo ip addr add 172.18.18.1/24 dev <adaptername>
    sudo ip link set <adaptername> up
    
Verify you can ping the master

    ping 172.18.18.101
    
Finally, add the cluster to your kubeconfig and activate the context

    kubectl config set-cluster vagrant-cluster --server=https://172.18.18.101:6443 --certificate-authority=$(pwd)/apiserver.crt
    kubectl config set-credentials vagrant-admin --username=admin --password=admin
    kubectl config set-context vagrant-admin --cluster=vagrant-cluster --user=vagrant-admin
    kubectl config use-context vagrant-admin
    
Verify your kubeconfig is working, for example:

    kubectl get pods
    

### Install Calico

From the main project directory:

    kubectl apply -f config/install/05-calico.yaml

 
### Install Istio
 
Install the Istio roles, bindings, and components.
 
    kubectl apply -f config/install/10-istio.yaml

When all components have started, you should see the pods in the `istio-system`
namespace similar to the following.
 
    kubectl get pods --namespace=istio-system 
 
    NAME                                 READY     STATUS    RESTARTS   AGE
    dikastes-node-ffcbl                  1/1       Running   0          20h
    dikastes-node-p2d3r                  1/1       Running   0          20h
    dikastes-node-w0b0x                  1/1       Running   0          20h
    istio-ca-3883180085-wdrqr            1/1       Running   0          20h
    istio-egress-1389168910-tfnh0        1/1       Running   0          20h
    istio-ingress-174722661-3fv5x        1/1       Running   0          20h
    istio-pilot-1557643696-zt8jg         1/1       Running   0          20h

You should see a `dikastes-node` pod for each host in your cluster.  Dikastes is a Calico component that computes
authorization policy for the Istio proxies on each host.  It is a separate component in this technical preview, but our
plan is to integrate it into the `calico-node` pod in future versions.

Note that Istio Mixer is not included in this demo because it is not required.  You can add a
Mixer deployment and [use it for telemetry or additional authorization checks](#can-i-use-dikastes-with-istio-mixer?).

Finally, add the initializer, which automatically adds the Istio Proxy sidecar to each deployment you add to your
cluster.

    kubectl apply -f config/install/20-istio-initializer.yaml
    
### Install the demo application

We will use a simple microservice application to demonstrate Calico application layer policy.  The [YAO Bank] 
application creates a customer-facing web application, a microservice that serves up account summaries, and an [etcd]
database.

    kubectl apply -f config/demo/10-yaobank.yaml

When the demo application has come up, you will see 3 pods.

    kubectl get pods
    
    NAME                        READY     STATUS    RESTARTS   AGE
    customer-2809159614-qqfnx   2/2       Running   0          21h
    database-1601951801-m4w70   2/2       Running   0          21h
    summary-2817688950-g1b3n    2/2       Running   0          21h
    
There is a Kubernetes ServiceAccount for each microservice in the application (in addition to the `default` account).

    kubectl get serviceaccount 

    NAME       SECRETS   AGE
    customer   1         21h
    database   1         21h
    default    1         21h
    summary    1         21h

Notice also that Istio CA will have created a secret of type `istio.io/key-and-cert` for each service account.  These
keys and X.509 certificates are used to cryptographically authenticate traffic in the Istio service mesh, and the 
corresponding service account identities are used by Dikastes in authorization policy.

    kubectl get secret 

    NAME                   TYPE                                  DATA      AGE
    customer-token-mgb8w   kubernetes.io/service-account-token   3         21h
    database-token-nb5xp   kubernetes.io/service-account-token   3         21h
    default-token-wwml6    kubernetes.io/service-account-token   3         21h
    istio.customer         istio.io/key-and-cert                 3         21h
    istio.database         istio.io/key-and-cert                 3         21h
    istio.default          istio.io/key-and-cert                 3         21h
    istio.summary          istio.io/key-and-cert                 3         21h
    summary-token-8kpt1    kubernetes.io/service-account-token   3         21h

### Determining Ingress IP & Port

You will use the `istio-ingress` service to access the YAO Bank application.

1. If your Kubernetes cluster is running in an environment that supports external load balancers, the IP address of 
   ingress can be  obtained by the following command:

   ```bash
   kubectl get ingress -o wide
   ```

   whose output should be similar to

   ```bash
   NAME      HOSTS     ADDRESS                 PORTS     AGE
   gateway   *         130.211.10.121          80        1d
   ```

   The address of the ingress service would then be
   
   ```bash
   export GATEWAY_URL=130.211.10.121:80
   ```

1. _GKE:_ Sometimes when the service is unable to obtain an external IP, `kubectl get ingress -o wide` may display a list of worker node addresses. In this case, you can use any of the addresses, along with the NodePort, to access the ingress. If the cluster has a firewall, you will also need to create a firewall rule to allow TCP traffic to the NodePort.

   ```bash
   export GATEWAY_URL=<workerNodeAddress>:$(kubectl get svc istio-ingress -n istio-system -o jsonpath='{.spec.ports[0].nodePort}')
   gcloud compute firewall-rules create allow-book --allow tcp:$(kubectl get svc istio-ingress -n istio-system -o jsonpath='{.spec.ports[0].nodePort}')
   ```

1. _IBM Bluemix Free Tier:_ External load balancer is not available for kubernetes clusters in the free tier in Bluemix. You can use the public IP of the worker node, along with the NodePort, to access the ingress. The public IP of the worker node can be obtained from the output of the following command:

   ```bash
   bx cs workers <cluster-name or id>
   export GATEWAY_URL=<public IP of the worker node>:$(kubectl get svc istio-ingress -n istio-system -o jsonpath='{.spec.ports[0].nodePort}')
   ```

1. _Vagrant:_ External load balancers are not supported in the Vagrant test cluster. You can use the host IP of the ingress service, along with the NodePort, to access the ingress.
   
   ```bash
   export GATEWAY_URL=$(kubectl get po -n istio-system -l istio=ingress -o 'jsonpath={.items[0].status.hostIP}'):$(kubectl get svc istio-ingress -n istio-system -o 'jsonpath={.spec.ports[0].nodePort}')
   ```

Point your browser to `http://$GATEWAY_URL/` to confirm the YAO Bank application is functioning correctly.  It may take
several minutes for all the services to come up and respond, during which time you may see 404 or 500 errors.

### The need for policy

Although Calico & Istio are running in the cluster, we have not defined any authorization policy.  Istio was configured
to mutually authenticate traffic between the pods in your application, so only connections with Istio-issued
certificates are allowed, and all inter-pod traffic is encrypted with TLS.  That's already a big step in the right
direction.

But, let's consider some deficiencies in this security architecture:

 * All incoming connections from workloads in the Istio mesh are equally trusted
 * Possession of a key & certificate pair is the *only* access credential considered.
 
To understand why these might be a problem, let's take them one at a time.

#### Trusting workloads

Trusting connections from any workload in
the Istio mesh is a poor security architecture because, like Kubernetes, Istio is designed to host multiple applications.  Some
of those applications may not be as trusted as others.  They may be operated by different users or teams with wildly
different security requirements.  We don't want our secure financial application microservices accessible from some
hacky prototype another developer is cooking up.

Even within our own application, the best practice is to limit access as much as possible.  Only pods that need access
to a service should get it.  Consider the YAO Bank application.  The customer web service does not need, and should not
have direct access to the backend database.  The customer web service needs to directly interact with clients outside
the cluster, some of whom may be malicious.  Unfortunately, vulnerabilities in web applications are all too common.  For
example, an [unpatched vulnerabiltiy in Apache Struts][struts cve] is what allowed attackers their initial access into
the Equifax network where they then launched a devastating attack to steal millions of people's financial information.

Imagine what would happen if an attacker were to gain control of the customer web pod in our application.

Let's simulate this by `exec`'ing into that pod.

    kubectl exec -ti customer-<fill in pod ID> -c customer bash

You should get a bash shell inside the customer pod.  Notice that from here, we get direct access to the backend
database.  For example, we can list all the entries in the database like this:

    curl http://database:2379/v2/keys?recursive=true | python -m json.tool

(Piping to `python -m json.tool` nicely formats the output.)

#### Single factor authorization

The possession of a key and certificate pair is a very strong assertion that a connection is authentic because it is
based on cryptographic proofs that are believed to be nearly impossible to forge.  When we authenticate connections this
way we can say with extremely high confidence that the party on the other end is in possession of the corresponding key.
However, this is only a proxy for what we actually want to be confident of: that the party on the other end really is
the authorized workload we want to communicate with.  Keeping the private key a secret is vital to this confidence, and
occasionally attackers can find ways to trick applications into giving up secrets they should not.  For example, the 
[Heartbleed] vulnerability in OpenSSL allowed attackers to trick an affected application into reading out portions of
its memory, compromising private keys (among other confidential information).

Let's simulate an attacker who has stolen the private keys of another pod.  Since the keys are stored as Kubernetes
secrets, we won't exploit a vulnerability in a service, but instead just mount the secret in a pod that will simulate an
attacker.

If you are still `exec`'d into the customer pod, exit out or open a new terminal tab (we will return the to the
customer pod later). 

    kubectl apply -f config/demo/20-attack-pod.yaml
    
Take a look at the `20-attack-pod.yaml` file in an editor.  It creates an `ubuntu` pod and mounts `istio.summary`
secret.  This will allow us to masquerade as if we were the `summary` service, even though this pod is not run as that
service account.  Let's try this out.  First, `exec` into the pod.

    kubectl exec -ti attack-<fill in pod ID> bash

Next, install the `curl` utility to initiate HTTP connections from the command line.

    apt update && apt install -y curl
    
Now, we will attack the database.  Instead of listing the contents like we did before, let's try something more 
malicious, like changing the account balance with a `PUT` command.


    curl -k https://database:2379/v2/keys/accounts/519940/balance -d value="10000.00" -XPUT --key /etc/certs/key.pem --cert /etc/certs/cert-chain.pem

Unlike when we did this with the customer web pod, we do not have the Istio Proxy to handle encryption, so we have to
pass an `https` URL, the `--key` and `--cert` parameters to `curl` to do the cryptography.

Return to your web browser and refresh to confirm the new balance.

#### Policy

We can mitigate both of the above deficiencies with a Calico policy.

You will need the latest (nightly) build of `calicoctl`.  Exit out of any pods you are exec'd into.

    wget https://www.projectcalico.org/builds/calicoctl
    chmod +x calicoctl
    
The policy uses alpha features of Calico behind a feature flag.  Enable these features.

    export ALPHA_FEATURES=serviceaccounts,httprules

Apply the sample policy.

    ./calicoctl create -f config/demo/30-policy.yaml

Let's examine this policy piece by piece.  It consists of 3 policy objects, one for each microservice.

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

This policy protects the customer web app.  Since this application is customer facing, we do not restrict what can
communicate with it.  We do, however, restrict that only HTTP `GET` requests are allowed.

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

The second policy protects the account summary microservice.  We know the only consumer of this service is the customer
web app, so we restrict the source of incoming connections to the service account for the customer web app.

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

The third policy protects the database.  Only the summary microservice should have direct access to the database.

Let's verify our policy is working as intended.  First, return to your browser and refresh, to ensure policy enforcement
has not broken the application.

Next, return to the customer web app.  Recall that we simulated an attacker gaining control of that pod by `exec`ing
into it.

    kubectl exec -ti customer-<fill in pod ID> -c customer bash

Repeat our attempt to access the database.

    curl http://database:2379/v2/keys?recursive=true

This time we should get a 403 Forbidden response (we have left out the JSON formatting because we do not expect to get
a valid JSON response).  Only the account summary microservice has database access according to our policy.

Finally, let's return to the attack pod that simulated stealing secret keys.

    kubectl exec -ti attack-<fill in pod ID> bash

Let's repeat our attack with stolen keys (we'll further increase the account balance to highlight whether it succeeds).

    curl -k https://database:2379/v2/keys/account/519940/balance -d value="99999.99" -XPUT --key /etc/certs/key.pem --cert /etc/certs/cert-chain.pem
    
If things are working correctly, you should get no response, and refreshing your browser should not show an increased
balance.

You might wonder how Calico was able to detect and prevent this attack---the attacker was able to steal the keys which
prove identity in our system.  This highlights the value of multi-layer authorization checks.  Although our attack pod
had the keys to fool the X.509 certificate check, Calico also monitors the Kubernetes API Server for which IP addresses
are associated with which service accounts.  Since our attack pod has an IP not associated with the account summary 
service account we disallow the connection.

## Known Limitations

This is an early access preview and it has not been fully integrated with all aspects of Calico.  In particular

 - Only GlobalNetworkPolicies are supported.  Calico NetworkPolicy objects cannot yet be used for Application Layer 
   Policy
 - Only `Allow` rules are fully supported.  The demo supports whitelisting traffic with allow rules.  More advanced use
   cases like mixing `Allow` and `Deny` rules are not yet supported.
 - The decision engine queries the Kube API Server on every request.  This is fine for small test applications, but
   will not scale to large clusters.  Future versions will integrate with the API sync functionality in `calico-node`.

## FAQ

#### Can I use Dikastes with Istio Mixer?

Yes, you can use Dikastes with Mixer.  Since Dikastes handles authorization checks, we expect most people will want to
use Mixer primarily for reporting telemetry.  Simply disable the Mixer checks (`disablePolicyChecks: true`), but keep 
report functionality on.  If you decide to use both Dikastes and Mixer for authorization checks, keep in mind that 
requests must pass both checks in order to be allowed.
 
 [calico]: https://projectcalico.org
 [istio]: https://istio.io
 [kubernetes]: https://kubernetes.io/
 [yao bank]: https://github.com/spikecurtis/yaobank
 [etcd]: https://github.com/coreos/etcd
 [struts cve]: https://nvd.nist.gov/vuln/detail/CVE-2017-5638
 [heartbleed]: http://heartbleed.com/
 [minikube]: https://github.com/kubernetes/minikube
 [initializers]: https://kubernetes.io/docs/admin/extensible-admission-controllers/
 [vagrant]: https://www.vagrantup.com/
 [virtualbox]: https://www.virtualbox.org/
