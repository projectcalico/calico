# Running on Semaphore

Noting current failures only, here:

## Batch 0

```
[error] 7.78% tests.st.bgp.test_global_config.TestBGP.test_bird_as_num: 24.9230s
[error] 0.54% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_5: 1.7433s
[error] 0.54% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_6: 1.7420s
[error] 0.53% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_12: 1.6829s
[error] 0.52% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_15: 1.6809s
[error] 0.52% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_13: 1.6548s
[error] 0.52% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_14: 1.6546s
[error] 0.51% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_11: 1.6361s
[error] 0.50% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_4: 1.6160s
[error] 0.50% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_10: 1.5998s
[error] 0.49% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_20: 1.5841s
[error] 0.46% tests.st.calicoctl.test_default_pools.TestDefaultPools.test_default_pools_23: 1.4880s
[error] 0.17% tests.st.bgp.test_global_config.TestBGP.test_defaults: 0.5532s
```

## Batch 1

```
Unable to find image 'calico/felix:master' locally
Error response from daemon: Get https://registry-1.docker.io/v2/: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)
```

## Batch 2

```
[fail] 7.37% tests.st.ipam.test_ipam.MultiHostIpam.test_pool_wrap_1: 4.1087s
[fail] 5.08% tests.st.ipam.test_ipam.MultiHostIpam.test_pools_add: 2.8290s
[fail] 4.53% tests.st.ipam.test_ipam.MultiHostIpam.test_pool_wrap_0: 2.5256s
```

## Batch 3

```
[error] 100.00% tests.st.bgp.test_route_reflector_cluster.TestRouteReflectorCluster.test_bird_route_reflector_cluster: 139.7196s
```

## Batch 4

```
[error] 30.63% tests.st.bgp.test_ipip.TestIPIP.test_gce_rr_0: 49.3337s
[error] 26.66% tests.st.bgp.test_ipip.TestIPIP.test_gce_rr_1: 42.9404s
[error] 23.66% tests.st.bgp.test_ipip.TestIPIP.test_gce_0: 38.1120s
[error] 11.84% tests.st.bgp.test_ipip.TestIPIP.test_gce_1: 19.0655s
[error] 7.10% tests.st.bgp.test_ipip.TestIPIP.test_ipip_0_bird: 11.4299s
[error] 0.12% tests.st.bgp.test_ipip.TestIPIP.test_ipip_addr_assigned: 0.1975s
```

## Batch 5

```
[fail] 9.80% tests.st.policy.test_profile.MultiHostMainline.test_rules_dest_ip_nets: 63.1726s
```
