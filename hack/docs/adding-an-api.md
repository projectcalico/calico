# How to add an API to Calico

Calico uses Kubernetes style APIs. To add a new API to Calico, or to add a new field to an existing API, use the following steps.

## Adding a new API field

For most cases, a new API field on an existing API is all that is needed. To add a new API field:

1. Update the structures in the [v3 API][v3]

1. Run `make generate` to update generated code and CRDs.

1. Add the new logic for your field, including [validation][validation].

1. Add unit tests for your field.

## Designing a new Calico API

1. Start by opening a GitHub issue or design document to design the feature. Consider the following:

   - What component(s) need to know about this resource?
   - What is the correct abstraction for this feature? 
   - Is there an existing API that makes sense for this feature instead?

1. Agree on a design for the new API. Read and follow the [Kubernetes API conventions][api-conventions] for new APIs.

1. Get your proposed API reviewed.

## Coding a new Calico API

1. Add the new structure to the [api/pkg/apis/projectcalico/v3][v3] in its own go file.

   - Include kubebuilder [validation and defaulting][kubebuilder] where appropriate.

1. Run code and CRD generation - `make generate`

1. Add client code to libcalico-go for the new API, using existing resources as a template.

   - https://github.com/projectcalico/calico/tree/master/libcalico-go/lib/clientv3
   - https://github.com/projectcalico/calico/blob/master/libcalico-go/lib/backend/k8s/k8s.go

1. Add unit tests for the API, using existing ones as a template.

1. Add CRUD commands and tests to calicoctl using existing ones as a template.

1. If felix or confd needs the new resource, add it to either the [felixsyncer][felixsyncer] or [bgpsyncer][bgpsyncer] respectively.

[api-conventions]: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md
[felixsyncer]: https://github.com/projectcalico/calico/blob/master/libcalico-go/lib/backend/syncersv1/felixsyncer/felixsyncerv1.go
[bgpsyncer]: https://github.com/projectcalico/calico/blob/master/libcalico-go/lib/backend/syncersv1/bgpsyncer/bgpsyncer.go
[v3]: https://github.com/projectcalico/calico/tree/master/api/pkg/apis/projectcalico/v3
[validation]: https://github.com/projectcalico/calico/tree/master/libcalico-go/lib/validator/v3
[kubebuilder]: https://book.kubebuilder.io/reference/markers/crd-validation.html
