# Disabling Calico Policy

The following two guides explain methods for disabling Calico policy on a running cluster. These steps are intended to be
used in the event that Calico policy is not functioning properly on a production system.

- [Overriding Calico Policy](override-policy.md) describes how to add high-priority Calico Global Network Policy to
  override the configured Network Policy and allow all traffic. We recommend using this approach first.
- [Disabling and Removing Calico Policy](remove-policy.md) describes how to fully disable Calico policy (removing all 
  Calico-programmed policy from each node. We recommend only using this approach only as a last resort.
  
