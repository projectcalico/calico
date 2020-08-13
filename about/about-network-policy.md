---
title: About Network Policy
description: Learn about networking!
---

> <span class="glyphicon glyphicon-info-sign"></span> This guide provides optional background education, including
> education that is not specific to {{site.prodname}}.
{: .alert .alert-info}



what is it
why is it needed and why do you want to use it
include david angle

k8s network policies
label selectors - like most other grouping of resources in k8s - both apply and in rules
ingress & egress allow rules only
default allow ingress or egress until policy applied to the pod that has ingress or egress rules
when applied can think of it as a virtual firewall running in front of the pod
allows are union - doesn't matter in what order you created the policies, and there is no ability to order them in terms
of spec

calico network policies
pre-dates k8s network policies
original reference implementation for k8s network policies
can use alongside k8s policies
offers more capabilities beyond k8s policies
one of the most noticeable differences is deny and log rules
therefore needs order
order allows you to put deny rules before k8s network policies
RBAC - ops team vs dev team example
CE for more of this including hierarchical policies
network sets
Istio integration - zero trust networking, multiple enforcement points without dual provisioning

best practices for network policies
ingress & egress
default deny, but with some exceptions such as DNS
policy per microservice is easiest
other options (find my diagram) also possible for example...




