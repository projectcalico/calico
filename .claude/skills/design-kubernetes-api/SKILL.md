---
name: design-kubernetes-api
description: Designs a best-practice, extensible Kubernetes API resource. Use when designing new API resources for Calico. 
---

## Workflow

- Start by finding out from the user, the proposed name, purpose and meaning of the new resource.
  - Namespaced or not?
  - Expected arity.
  - Relationship to other resources (ownership/peer/selection-based links?).
- Try to get a full list of the current aspects of the resource that need to be configured and the "direction of travel" for extensions to those in future.
- Propose and iterate on a custom resource design.
- Follow the best practices outlined in the Kubernetes API conventions
  at https://raw.githubusercontent.com/kubernetes/community/refs/heads/master/contributors/devel/sig-architecture/api-conventions.md
- In particular:
  - Avoid booleans, in favour of enums that can be extended later. If in doubt, use Enabled/Disabled in place of a bool.
    *NO* fooBarEnabled: true | false
    *YES* fooBar: Enabled | Disabled
  - Follow naming schemes laid out there:
    - lowerCamel for field names
    - UpperCamel for enum values 
- Place a lot of weight on future maintenance and extension.
  - Many Calico resources (such as FelixConfiguration and NetworkPolicy are poor examples, they use large "bag" structs).
  - Group aspects of the object into sub-structs
  - Make use of the union pattern for controlling alternation with efficient kubebuilder annotations instead of requiring custom inter-field validation.
- Consider ergonomics of using the new resource with kubectl; propose suitable kubebuilder annotations to print useful columns.
- Consider including a status sub-resource if the resource will naturally be operated upon by a kubernetes controller.
- When designing policy-related structs or similar, it's generally better to have separate structs for "ingress" and "egress" rule types, even if they are identical right now. Over time they tend to diverge.
- Avoid custom int-or-string fields in most cases. It's OK to use existing types but it's generally better to use unions.
- Review the naming and structure critically for consistency. Pay attention to suffix and prefix usage. Fields representing similar concepts should "read as siblings".

### Union pattern

This is a common pattern in Kubernetes APIs that allows extension over time.  It avoids bloating a parent struct with many fields that are mutually exclusive.  For example, the various flavours of port/protocol match in a network policy rule may be expressed like this:

```
port:
  number: 8080
```

or 

```
port:
  range:
    min: 8000
    max: 8080
```

or

```
port:
  name: some-named-port
```

Pros:
- YAML read well.
- Expresses alternation structurally rather than with out-of-band validation.
- Go structs can express the kube-builder validation efficiently with these annotations on the struct.
  ```
  // +kubebuilder:validation:MaxProperties=1
  // +kubebuilder:validation:MinProperties=1  // If one must be provided
  ```
- Always extensible by adding new alternation option.
Cons:
- We're stuck with the top-level name, "ports" in my example. Choose wisely and opt for something general.
- Can "stutter" if the obvious name for an inner field is the same as the outer.
- Can suffer combinatorial explosion if later want to mix and match formerly-orthogonal aspects. (For example, extending the above to support some new match.)
  This is generally manageable, and it can be side-stepped if needed by introducing a general purpose node.  Contrived example:

```
port:
  mustMatchAll:
  - range:
      min: 8000
      max: 8080
  - portRemainder:
      modulo: 3
      remainder: 1
```

### Selectors

Calico API's typically use our selector syntax instead of Kubernetes 
matchLabels and similar.

New APIs should avoid matching multiple resource types with the same selector. 
We've learned that matching workload endpoints, host endpoints and network 
sets with the same selector is confusing, for example.  Prefer one selector per
type of thing that is matched.

Be critical of the need for a selector, referencing a single item by 
name/namespace is often simpler for the user. For example, we've found that 
most uses of network sets simply use a name label on the network set and select
on that.

When selecting namespaced resources, use split namespaceSelector and 
itemTypeSelector.

### Calico naming conventions.

- Our API is slightly more general than Kubernetes, "pods" and OpenStack VMs map to "workloads" in our model.
- When referring to concepts from outside calico, try to use the most broadly adopted industry terms.  Consider alternatives and back up your choices.

## Output guide:

- Generally best to iterate on the YAML to start with until it looks good - this is how the user will interact with it, but give the option to present the Go structs too.
- When presenting yaml, it's helpful to show the allowed alternatives inline, even if they wouldn't be valid in a real resource.  For example, you could present a union like this:
```
port:                                                                           
  number: 8080                                                      

  # Or... 
  range:                                                                        
    min: 8000                                                                   
    max: 8080
  
  # Or...
  namedPort: foo

```
- Go structs should include
  - Comments suitable for end-user documentation (these will be picked up by the CRD schema generator).
  - kubebuilder annotations for default values (where appropriate) and validation of enums and integer ranges.
  - json field tags as needed
  - for complex validation of custom types (avoid if possible) validation tags on the fields (these are interpreted by our custom validator in libcalico-go/lib/validator.
- Review the go structs field by field, explaining the proposed kube-builder annotations and validation.
