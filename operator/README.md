# Calico Operator

[![Docker image](https://img.shields.io/badge/docker-quay.io%2Ftigera%2Foperator-blue)](https://quay.io/repository/tigera/operator)

This repository contains a Kubernetes operator which manages the lifecycle of a Calico or Calico Enterprise installation on Kubernetes or OpenShift. Its goal is
to make installation, upgrades, and ongoing lifecycle management of Calico and Calico Enterprise as simple and reliable as possible.

This operator is built using the [operator-sdk](https://github.com/operator-framework/operator-sdk), so you should be familiar with how that works before getting started.

## Getting Started Running Calico

There are many avenues to get started running Calico depending on your situation.

- Trying out Kubernetes on a single host or on your own hardware? The [quick start guide](https://projectcalico.docs.tigera.io/getting-started/kubernetes/quickstart) will have you up and running in about fifteen minutes.
- Running a managed public cloud? Use our guides for enabling Calico network policies.
  - [Amazon Elastic Kubernetes Service (EKS)](https://docs.tigera.io/calico/latest/getting-started/kubernetes/managed-public-cloud/eks)
  - [Google Kubernetes Engine (GKE)](https://docs.tigera.io/calico/latest/getting-started/kubernetes/managed-public-cloud/gke)
  - [IBM Cloud Kubernetes Service (IKS)](https://docs.tigera.io/calico/latest/getting-started/kubernetes/managed-public-cloud/iks)
  - [Microsoft Azure Kubernetes Service (AKS)](https://docs.tigera.io/calico/latest/getting-started/kubernetes/managed-public-cloud/aks)
- Want to go deeper? Visit [https://docs.tigera.io/](https://docs.tigera.io/) for full documentation.

## Get Started Developing

See [the developer guidelines](docs/dev_guidelines.md) for more information on designing, coding, and testing changes.
