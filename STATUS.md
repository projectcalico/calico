# Running on Semaphore

Noting current failures only, here:

## Batch 0

(no failures)

## Batch 1

```
[error] 41.86% tests.st.bgp.test_single_route_reflector.TestSingleRouteReflector.test_bird_single_route_reflector: 54.5856s
[error] 32.39% tests.st.bgp.test_global_peers.TestGlobalPeers.test_bird_node_peers: 42.2450s
[error] 25.75% tests.st.bgp.test_node_peers.TestNodePeers.test_bird_node_peers: 33.5787s
```

## Batch 2

```
[fail] 7.18% tests.st.ipam.test_ipam.MultiHostIpam.test_pool_wrap_1: 4.0287s
[fail] 4.95% tests.st.ipam.test_ipam.MultiHostIpam.test_pools_add: 2.7787s
[fail] 4.63% tests.st.ipam.test_ipam.MultiHostIpam.test_pool_wrap_0: 2.5973s
```

## Batch 3

```
[error] 100.00% tests.st.bgp.test_route_reflector_cluster.TestRouteReflectorCluster.test_bird_route_reflector_cluster: 134.2365s
```

## Batch 4

```
[error] 34.45% tests.st.bgp.test_ipip.TestIPIP.test_gce_rr_0: 51.7408s
[error] 25.22% tests.st.bgp.test_ipip.TestIPIP.test_gce_rr_1: 37.8825s
[error] 20.46% tests.st.bgp.test_ipip.TestIPIP.test_gce_0: 30.7323s
[error] 12.73% tests.st.bgp.test_ipip.TestIPIP.test_gce_1: 19.1237s
[error] 7.02% tests.st.bgp.test_ipip.TestIPIP.test_ipip_0_bird: 10.5377s
[error] 0.12% tests.st.bgp.test_ipip.TestIPIP.test_ipip_addr_assigned: 0.1829s
```

## Batch 5

In the SSL tests (make st-ssl):
```
CalledProcessError: Command 'docker exec calico-etcd sh -c 'ETCDCTL_API=3 etcdctl del --prefix /calico'' returned non-zero exit status 1
```
