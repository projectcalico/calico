Understanding scopes and the `all()` and `global()` operators:  selectors have a scope of resources
that they are matched against, which depends on the context in which they are used.  For example:

* The `nodeSelector` in an `IPPool` selects over `Node` resources.

* The top-level selector in a `NetworkPolicy` selects over the workloads _in the same namespace_ as the 
  `NetworkPolicy`.
  
* The top-level selector in a `GlobalNetworkPolicy` doesn't have the same restriction, it selects over all endpoints
  including namespaced `WorkloadEndpoint`s and non-namespaced `HostEndpoint`s.

* The `namespaceSelector` in a `NetworkPolicy` (or `GlobalNetworkPolicy`) _rule_ selects over the labels on namespaces 
  rather than workloads.

* The `namespaceSelector` determines the scope of the accompanying `selector` in the entity rule.  If no `namespaceSelector`
  is present then the rule's `selector` matches the default scope for that type of policy.  (This is the same namespace
  for `NetworkPolicy` and all endpoints/network sets for `GlobalNetworkPolicy`)
  
* The `global()` operator can be used (only) in a `namespaceSelector` to change the scope of the main `selector` to 
  include non-namespaced resources such as [GlobalNetworkSet]({{ site.baseurl }}/reference/resources/globalnetworkset).
  This allows namespaced `NetworkPolicy` resources to refer to global non-namespaced resources, which would otherwise
  be impossible.
