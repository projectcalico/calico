# Dikastes - The Decider.

Dikastes is a component of [Project Calico][calico] for enforcing network and application layer authorization policies using [Istio].
 
## Getting Started
 
This guide explains how to install Istio with Dikastes into your cluster, and use it to
enforce authorization policies in a simple demo application.
 
 ### Prerequisites
 
This demo will run on a Calico-enabled Kubernetes cluster.
 
 * A [Kubernetes][kubernetes] cluster running v1.8 with the following features enabled
   * RBAC
   * Initializers
 * Calico v3.0 (beta) with the Kubernetes Data Store
 
If you have Istio installed, remove it from the cluster.  Dikastes relies on several 
custom-built Istio components which will be installed in the demo.
 
### Install Istio
 
Install the Istio and Dikastes roles, bindings, and components.
 
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

You should see a `dikastes-node` pod for each host in your cluster.

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

1. _Minikube:_ External load balancers are not supported in Minikube. You can use the host IP of the ingress service, along with the NodePort, to access the ingress.
   
   ```bash
   export GATEWAY_URL=$(kubectl get po -n istio-system -l istio=ingress -o 'jsonpath={.items[0].status.hostIP}'):$(kubectl get svc istio-ingress -n istio-system -o 'jsonpath={.spec.ports[0].nodePort}')
   ```

Point your browser to `http://$GATEWAY_URL/` to confirm the YAO Bank application is functioning correctly.

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
    
Take a look at the `30-attack-pod.yaml` file in an editor.  It creates an `ubuntu` pod and mounts `istio.summary`
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

We can mitigate both of the above deficiencies with a Calico policy.  Apply the sample policy.

    calicoctl create -f config/demo/30-policy.yaml

Let's examine this policy piece by piece.  It consists of 3 policy objects, one for each microservice.

    apiVersion: v1
    kind: policy
    metadata:
      name: customer
    spec:
      selector: app == 'customer'
      ingress:
        - action: allow
          http:
            methods: ["GET"]
      egress:
        - action: allow

This policy protects the customer web app.  Since this application is customer facing, we do not restrict what can
communicate with it.  We do, however, restrict that only HTTP `GET` requests are allowed.

    apiVersion: v1
    kind: policy
    metadata:
      name: summary
    spec:
      selector: app == 'summary'
      ingress:
        - action: allow
          source:
            serviceAccounts:
              namespace: default
              names: ["customer"]
      egress:
        - action: allow

The second policy protects the account summary microservice.  We know the only consumer of this service is the customer
web app, so we restrict the source of incoming connections to the service account for the customer web app.

    apiVersion: v1
    kind: policy
    metadata:
      name: database
    spec:
      selector: app == 'database'
      ingress:
        - action: allow
          source:
            serviceAccounts:
              namespace: default
              names: ["summary"]
      egress:
        - action: allow

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
 [struts cve]https://nvd.nist.gov/vuln/detail/CVE-2017-5638
 [heartbleed] http://heartbleed.com/