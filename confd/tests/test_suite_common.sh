#!/bin/bash

trap 'echo "\nCaught signal, exiting...\n"; exit 1' SIGINT SIGTERM

: ${UPDATE_EXPECTED_DATA:=false}

CALICOCTL="calicoctl --allow-version-mismatch"

# Execute the suite of tests.  It is assumed the following environment variables will
# have been set up beforehand:
# -  DATASTORE_TYPE + other calico datastore envs
# -  LOGPATH
execute_test_suite() {
    # This is needed for two reasons:
    # -  to substitute for "NODENAME" in some of the cond TOML files
    # -  for the confd Calico client to select which node to listen to for key events.
    export NODENAME="kube-master"

    # Make sure the log and rendered templates paths are created and old test run data is
    # deleted.
    mkdir -p $LOGPATH
    mkdir -p $LOGPATH/rendered
    rm $LOGPATH/log* || true
    rm $LOGPATH/rendered/*.cfg || true

    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        run_extra_test test_node_mesh_bgp_password
        run_extra_test test_bgp_password_deadlock
        run_extra_test test_bgp_ttl_security
        run_extra_test test_bgp_ignored_interfaces
        run_extra_test test_bgp_reachable_by
        run_extra_test test_bgp_filters
        run_extra_test test_bgp_local_bgp_peer
        run_extra_test test_bgp_next_hop_mode
        run_extra_test test_bgp_reverse_peering
    fi

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
        run_extra_test test_node_mesh_bgp_password
        run_extra_test test_bgp_password
        run_extra_test test_bgp_sourceaddr_gracefulrestart
        run_extra_test test_node_deletion
        run_extra_test test_idle_peers
        run_extra_test test_router_id_hash
        run_extra_test test_bgp_ttl_security
        run_extra_test test_bgp_ignored_interfaces
        run_extra_test test_bgp_reachable_by
        run_extra_test test_bgp_filters
        run_extra_test test_bgp_next_hop_mode
        echo "Extra etcdv3 tests passed"
    fi

    # Run the set of tests using confd in oneshot mode.
    echo "Execute oneshot-mode tests"
    execute_tests_oneshot
    echo "Oneshot-mode tests passed"

    # Now run a set of tests with confd running continuously.
    # Note that changes to the node to node mesh config option will result in a restart of
    # confd, so order the tests accordingly.  We'll start with a set of tests that use the
    # node mesh enabled, so turn it on now before we start confd.
    echo "Execute daemon-mode tests"
    turn_mesh_on
    for i in $(seq 1 2); do
       execute_tests_daemon
    done
    echo "Daemon-mode tests passed"
}

run_extra_test() {
    test_fn=$1
    echo
    echo "Run test: $1"
    echo "==============================="
    eval $1
    echo "==============================="
}

test_bgp_password() {
    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=node1 BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off.
    turn_mesh_off

    # Create 4 nodes with various password peerings.
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node1
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.1/24
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node2
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.2/24
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node3
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.3/24
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node4
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.4/24
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: bgppeer-1
spec:
  nodeSelector: has(node)
  peerIP: 10.24.0.2
  asNumber: 64512
  password:
    secretKeyRef:
      name: my-secrets-1
      key: a
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: bgppeer-2
spec:
  nodeSelector: has(node)
  peerIP: 10.24.0.3
  asNumber: 64512
  password:
    secretKeyRef:
      name: my-secrets-1
      key: b
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: bgppeer-3
spec:
  node: node1
  peerIP: 10.24.10.10
  asNumber: 64512
  password:
    secretKeyRef:
      name: my-secrets-2
      key: c
EOF

    # Expect 3 peerings, all with no password because we haven't
    # created the secrets yet.
    test_confd_templates password/step1

    # Create my-secrets-1 secret with only one of the required keys.
    kubectl create -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-secrets-1
  namespace: kube-system
type: Opaque
stringData:
  b: password-b
EOF

    # Expect password now on the peering using my-secrets-1/b.
    test_confd_templates password/step2

    # Update my-secrets-1 secret with the other required key.
    kubectl replace -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-secrets-1
  namespace: kube-system
type: Opaque
stringData:
  b: password-b
  a: password-a
EOF

    # Also create my-secrets-2 secret.
    kubectl create -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-secrets-2
  namespace: kube-system
type: Opaque
stringData:
  c: password-c
EOF

    # Expect passwords on all peerings.
    test_confd_templates password/step3

    # Delete a secret.
    kubectl delete secret my-secrets-2 -n kube-system

    # Expect password-c to have disappeared.
    test_confd_templates password/step4

    # Change the passwords in the other secret.
    kubectl replace -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-secrets-1
  namespace: kube-system
type: Opaque
stringData:
  b: new-password-b
  a: new-password-a
EOF

    # Expect peerings to have new passwords.
    test_confd_templates password/step5

    # Delete one of the keys from that secret.
    kubectl replace -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-secrets-1
  namespace: kube-system
type: Opaque
stringData:
  b: new-password-b
EOF

    # Expect new-password-a to have disappeared.
    test_confd_templates password/step6

    # Delete the remaining secret.
    kubectl delete secret my-secrets-1 -n kube-system

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete node node1
    $CALICOCTL delete node node2
    $CALICOCTL delete node node3
    $CALICOCTL delete node node4
    $CALICOCTL delete bgppeer bgppeer-1
    $CALICOCTL delete bgppeer bgppeer-2

    # Check that passwords were not logged.
    password_logs="`grep 'password-' $LOGPATH/logd1 || true`"
    echo "$password_logs"
    if [ "$password_logs" ]; then
        echo "ERROR: passwords were logged"
        return 1
    fi
}

test_bgp_password_deadlock() {
    # For this test we populate the datastore before starting confd.
    # Also we use Typha.
    start_typha

    # Clean up the output directory.
    rm -f /etc/calico/confd/config/*

    # Turn the node-mesh off.
    turn_mesh_off

    # Adjust this number until confd's iteration through BGPPeers
    # takes longer than 100ms.  That is what's needed to see the
    # deadlock.
    SCALE=99

    # Create $SCALE nodes and BGPPeer configs.
    for ii in `seq 1 $SCALE`; do
        kubectl apply -f - <<EOF
apiVersion: v1
kind: Node
metadata:
  annotations:
    node.alpha.kubernetes.io/ttl: "0"
    volumes.kubernetes.io/controller-managed-attach-detach: "true"
  labels:
    kubernetes.io/arch: amd64
    kubernetes.io/os: linux
    kubernetes.io/hostname: node$ii
  name: node$ii
  namespace: ""
spec:
  externalID: node$ii
EOF
        $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node$ii
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.$ii/24
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: bgppeer-$ii
spec:
  node: node$ii
  peerIP: 10.24.0.2
  asNumber: 64512
  password:
    secretKeyRef:
      name: my-secrets-1
      key: a
EOF
    done

    # Create the required secret.
    kubectl create -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-secrets-1
  namespace: kube-system
type: Opaque
stringData:
  a: password-a
EOF

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=node1 BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Expect BIRD config to be generated.
    test_confd_templates password-deadlock

    # Kill confd.
    kill -9 $CONFD_PID

    # Kill Typha.
    kill_typha

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete resources.
    kubectl delete secret my-secrets-1 -n kube-system
    for ii in `seq 1 $SCALE`; do
        $CALICOCTL delete bgppeer bgppeer-$ii
        kubectl delete node node$ii
    done
}

test_node_deletion() {
    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=node1 BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off.
    turn_mesh_off

    # Create 4 nodes with a mesh of peerings.
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node1
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.1/24
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node2
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.2/24
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node3
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.3/24
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node4
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.4/24
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: bgppeer-1
spec:
  nodeSelector: has(node)
  peerSelector: has(node)
EOF

    # Expect 3 peerings.
    expect_peerings 3

    # Delete one of the nodes.
    $CALICOCTL delete node node3

    # Expect just 2 peerings.
    expect_peerings 2

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete node node1
    $CALICOCTL delete node node2
    $CALICOCTL delete node node4
    $CALICOCTL delete bgppeer bgppeer-1
}

# Test that when BGPPeers generate overlapping global and node-specific peerings, we reliably
# only see the global peerings in the v1 data model.
test_idle_peers() {
    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=node1 BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off.
    turn_mesh_off

    # Create 2 nodes, a global peering between them, and a node-specific peering between them.
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node1
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.1/24
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node2
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.2/24
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: node-specific
spec:
  node: node1
  peerSelector: has(node)
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: global
spec:
  peerSelector: has(node)
EOF

    # Expect 1 peering.
    expect_peerings 1

    # 10 times, touch a Node resource to cause peerings to be recomputed, and check that we
    # always see just one peering.
    for n in `seq 1 10`; do
        $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node1
  labels:
    node: yes
spec:
  bgp:
    ipv4Address: 10.24.0.1/24
EOF
        sleep 0.25
        expect_peerings 1
    done

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete resources.  Note that deleting Node node1 also deletes the node-specific BGPPeer.
    $CALICOCTL delete node node1
    $CALICOCTL delete node node2
    $CALICOCTL delete bgppeer global
}

expect_peerings() {
    expected_count=$1
    attempts=0
    while sleep 1; do
        grep "protocol bgp" /etc/calico/confd/config/bird.cfg
        count=`grep "protocol bgp" /etc/calico/confd/config/bird.cfg | wc -l`
        if [ "$count" = "$expected_count" ]; then
            break
        fi
        let 'attempts += 1'
        echo Failed attempts = $attempts
        if [ "$attempts" -gt 5 ]; then
            echo Test failed
            cat /etc/calico/confd/config/bird.cfg
            return 2
        fi
    done
}

# Execute a set of tests using daemon mode.
execute_tests_daemon() {
    # For KDD, run Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Run the node-mesh-enabled tests.
    for i in $(seq 1 2); do
        run_individual_test 'mesh/bgp-export'
        run_individual_test 'mesh/ipip-always'
        run_individual_test 'mesh/ipip-cross-subnet'
        run_individual_test 'mesh/ipip-off'
        run_individual_test 'mesh/route-reflector-mesh-enabled'
        run_individual_test 'mesh/static-routes'
        run_individual_test 'mesh/static-routes-exclude-node'
        run_individual_test 'mesh/communities'
        run_individual_test 'mesh/restart-time'
    done

    # Turn the node-mesh off.
    turn_mesh_off

    # Run the explicit peering tests.
    for i in $(seq 1 2); do
        run_individual_test 'explicit_peering/global'
        run_individual_test 'explicit_peering/global-external'
        run_individual_test 'explicit_peering/global-ipv6'
        run_individual_test 'explicit_peering/specific_node'
        run_individual_test 'explicit_peering/selectors'
        run_individual_test 'explicit_peering/route_reflector'
        run_individual_test 'explicit_peering/keepnexthop'
        run_individual_test 'explicit_peering/keepnexthop-global'
        run_individual_test 'explicit_peering/local-as-ipv6'
        run_individual_test 'explicit_peering/local-as-global-ipv6'
        run_individual_test 'explicit_peering/local-as'
        run_individual_test 'explicit_peering/local-as-global'
    done

    # Turn the node-mesh back on.
    turn_mesh_on

    # Kill confd.
    kill -9 $CONFD_PID

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

# Execute a set of tests using oneshot mode.
execute_tests_oneshot() {
    # Note that changes to the node to node mesh config option will result in a restart of
    # confd, so order the tests accordingly.  Since the default nodeToNodeMeshEnabled setting
    # is true, perform the mesh tests first.  Then run the explicit peering tests - we should
    # see confd terminate when we turn of the mesh.
    for i in $(seq 1 2); do
        run_individual_test_oneshot 'mesh/bgp-export'
        run_individual_test_oneshot 'mesh/ipip-always'
        run_individual_test_oneshot 'mesh/ipip-cross-subnet'
        run_individual_test_oneshot 'mesh/ipip-off'
        run_individual_test_oneshot 'mesh/vxlan-always'
        run_individual_test_oneshot 'explicit_peering/global'
        run_individual_test_oneshot 'explicit_peering/specific_node'
        run_individual_test_oneshot 'explicit_peering/selectors'
        run_individual_test_oneshot 'explicit_peering/route_reflector'
        run_individual_test_oneshot 'explicit_peering/route_reflector_v6_by_ip'
        run_individual_test_oneshot 'mesh/static-routes'
        run_individual_test_oneshot 'mesh/static-routes-exclude-node'
        run_individual_test_oneshot 'mesh/communities'
        run_individual_test_oneshot 'mesh/restart-time'
        run_individual_test_oneshot 'explicit_peering/keepnexthop'
        run_individual_test_oneshot 'explicit_peering/keepnexthop-global'
        export CALICO_ROUTER_ID=10.10.10.10
        run_individual_test_oneshot 'mesh/static-routes-no-ipv4-address'
        export -n CALICO_ROUTER_ID
        unset CALICO_ROUTER_ID
    done
}


# Turn the node-to-node mesh off.
turn_mesh_off() {
    $CALICOCTL apply -f - <<EOF
kind: BGPConfiguration
apiVersion: projectcalico.org/v3
metadata:
  name: default
spec:
  nodeToNodeMeshEnabled: false
EOF
}

# Turn the node-to-node mesh on.
turn_mesh_on() {
    $CALICOCTL apply -f - <<EOF
kind: BGPConfiguration
apiVersion: projectcalico.org/v3
metadata:
  name: default
spec:
  nodeToNodeMeshEnabled: true
EOF
}

# Run an individual test using confd in daemon mode:
# - apply a set of resources using calicoctl
# - verify the templates generated by confd as a result.
run_individual_test() {
    testdir=$1
    testdir_save=$testdir

    # Populate Calico using calicoctl to load the input.yaml test data.
    echo "Populating calico with test data using calicoctl: " $testdir
    $CALICOCTL apply -f /tests/mock_data/calicoctl/${testdir}/input.yaml

    # Populate Kubernetes API with data if it exists for this test.
    if [[ -f /tests/mock_data/calicoctl/${testdir}/kubectl-input.yaml ]]; then
            KUBECONFIG=/home/user/certs/kubeconfig kubectl apply -f /tests/mock_data/calicoctl/${testdir}/kubectl-input.yaml
    fi

    # Check the confd templates are updated.
    test_confd_templates $testdir

    if [ -f /tests/mock_data/calicoctl/${testdir}/step2/input.yaml ]; then
        echo "Config changes for step 2"
        $CALICOCTL apply -f /tests/mock_data/calicoctl/${testdir}/step2/input.yaml

        # Check config changes as expected.
        test_confd_templates ${testdir}/step2

        # That changes testdir, so undo that change.
        testdir=$testdir_save
    fi

    # Remove any resource that does not need to be persisted due to test environment
    # limitations.
    echo "Preparing Calico data for next test"
    if [[ -f /tests/mock_data/calicoctl/${testdir}/kubectl-delete.yaml ]]; then
            KUBECONFIG=/home/user/certs/kubeconfig kubectl delete -f /tests/mock_data/calicoctl/${testdir}/kubectl-delete.yaml
    fi

    if [ -f /tests/mock_data/calicoctl/${testdir}/step2/delete.yaml ]; then
        $CALICOCTL delete -f /tests/mock_data/calicoctl/${testdir}/step2/delete.yaml
    fi
    $CALICOCTL delete -f /tests/mock_data/calicoctl/${testdir}/delete.yaml
}

# Run an individual test using oneshot mode:
# - applying a set of resources using calicoctl
# - run confd in oneshot mode
# - verify the templates generated by confd as a result.
run_individual_test_oneshot() {
    testdir=$1

    # Populate Calico using calicoctl to load the input.yaml test data.
    echo "Populating calico with test data using calicoctl: " $testdir
    $CALICOCTL apply -f /tests/mock_data/calicoctl/${testdir}/input.yaml

    # Populate Kubernetes API with data if it exists for this test.
    if [[ -f /tests/mock_data/calicoctl/${testdir}/kubectl-input.yaml ]]; then
            KUBECONFIG=/home/user/certs/kubeconfig kubectl apply -f /tests/mock_data/calicoctl/${testdir}/kubectl-input.yaml
    fi

    # For KDD, run Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
    fi

    # Clean up the output directory.
    rm -f /etc/calico/confd/config/*

    # Run confd in oneshot mode.
    BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd -onetime >$LOGPATH/logss 2>&1 || true

    # Check the confd templates are updated.
    test_confd_templates $testdir

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi

    # Remove any resource that does not need to be persisted due to test environment
    # limitations.
    echo "Preparing Calico data for next test"
    if [[ -f /tests/mock_data/calicoctl/${testdir}/kubectl-delete.yaml ]]; then
            KUBECONFIG=/home/user/certs/kubeconfig kubectl delete -f /tests/mock_data/calicoctl/${testdir}/kubectl-delete.yaml
    fi
    $CALICOCTL delete -f /tests/mock_data/calicoctl/${testdir}/delete.yaml
}

start_typha() {
    echo "Starting Typha"
    TYPHA_DATASTORETYPE=kubernetes \
        KUBECONFIG=/home/user/certs/kubeconfig \
        TYPHA_LOGSEVERITYSCREEN=debug \
        TYPHA_LOGSEVERITYSYS=none \
        TYPHA_LOGFILEPATH=none \
        typha >$LOGPATH/typha 2>&1 &
    TYPHA_PID=$!

    # Set variables needed for confd to connect to Typha.
    export FELIX_TYPHAADDR=127.0.0.1:5473
    export FELIX_TYPHAREADTIMEOUT=50

    # Allow a little time for Typha to start up and start listening.
    #
    # If Typha isn't ready when confd tries to connect to it, confd drops a FATAL
    # log and exits.  You might think that confd should retry, but our general
    # design (e.g. what Felix also does) here is to exit and be restarted by the
    # surrounding service framework.
    sleep 0.25

    # Avoid getting bash's "Killed" message in the output when we kill Typha.
    disown %?typha
}

kill_typha() {
    echo "Killing Typha"
    kill -9 $TYPHA_PID 2>/dev/null
}

# Tests that confd generates the required set of templates for the test.
# $1 would be the tests you want to run e.g. mesh/global
test_confd_templates() {
    # Compare the templates until they match (for a max of 10s).
    testdir=$1
    echo "Comparing with templates in $testdir"
    for i in $(seq 1 10); do echo "comparing templates attempt $i" && compare_templates $testdir 0 false && break || sleep 1; done
    compare_templates $testdir 1 ${UPDATE_EXPECTED_DATA}
}

# Compares the generated templates against the known good templates
# $1 would be the tests you want to run e.g. mesh/global
# $2 is whether or not we should output the diff results (0=no)
compare_templates() {
    # Check the generated templates against known compiled templates.
    testdir=$1
    output=$2
    record=$3
    rc=0
    for f in `ls /tests/compiled_templates/${testdir}`; do
        if [ $f = step2 ]; then
	    # Some tests have a "step2" subdirectory.  If so, the BIRD
	    # config in that subdir will be used when
	    # compare_templates is called again with ${testdir}/step2.
	    # This time through, we should skip "step2" because there
	    # is nothing matching it in the actual generated config at
	    # /etc/calico/confd/config/.
            continue
        fi
        expected=/tests/compiled_templates/${testdir}/${f}
        actual=/etc/calico/confd/config/${f}
        if ! diff --ignore-blank-lines -q ${expected} ${actual} 1>/dev/null 2>&1; then
            if ! $record; then
                rc=1;
            fi
            if [ $output -ne 0 ]; then
                echo "Failed: $f templates do not match, showing diff of expected vs received"
                set +e
                diff ${expected} ${actual}
                if $record; then
                    echo "Updating expected result..."
                    cp ${actual} ${expected}
                else
                    echo "Copying confd rendered output to ${LOGPATH}/rendered/${f}"
                    cp ${actual} ${LOGPATH}/rendered/${f}
                    set -e
                    rc=2
                fi
            fi
        fi
    done

    if [ $rc -eq 2 ]; then
        echo "Recording failed testcase directory to ${LOGPATH}/testcase_directory.txt"
        echo "${testdir}" > ${LOGPATH}/testcase_directory.txt
        echo "Copying nodes to ${LOGPATH}/nodes.yaml"
        $CALICOCTL get nodes -o yaml > ${LOGPATH}/nodes.yaml
        echo "Copying bgp config to ${LOGPATH}/bgpconfig.yaml"
        $CALICOCTL get bgpconfigs -o yaml > ${LOGPATH}/bgpconfig.yaml
        echo "Copying bgp peers to ${LOGPATH}/bgppeers.yaml"
        $CALICOCTL get bgppeers -o yaml > ${LOGPATH}/bgppeers.yaml
        echo "Copying bgp filters to ${LOGPATH}/bgpfilters.yaml"
        $CALICOCTL get bgpfilters -o yaml > ${LOGPATH}/bgpfilters.yaml
        echo "Copying ip pools to ${LOGPATH}/ippools.yaml"
        $CALICOCTL get ippools -o yaml > ${LOGPATH}/ippools.yaml
        echo "Listing running processes"
        ps
    fi

    return $rc
}

test_router_id_hash() {
    export CALICO_ROUTER_ID=hash
    run_individual_test_oneshot 'mesh/hash'
    export -n CALICO_ROUTER_ID
    unset CALICO_ROUTER_ID
}

test_bgp_sourceaddr_gracefulrestart() {
    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=node1 BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off.
    turn_mesh_off

    # Create 2 nodes with IPs directly on a local subnet, and a
    # peering between them.
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node1
spec:
  bgp:
    ipv4Address: 172.17.0.5/24
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: node2
spec:
  bgp:
    ipv4Address: 172.17.0.6/24
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: bgppeer-1
spec:
  node: node1
  peerIP: 172.17.0.6
  asNumber: 64512
EOF

    # Expect a "direct" peering.
    test_confd_templates sourceaddr_gracefulrestart/step1

    # Change the peering to omit source address.
    $CALICOCTL apply -f - <<EOF
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: bgppeer-1
spec:
  node: node1
  peerIP: 172.17.0.6
  asNumber: 64512
  sourceAddress: None
EOF

    # Expect direct peering without source address.
    test_confd_templates sourceaddr_gracefulrestart/step2

    # Change the peering to specify max restart time.
    $CALICOCTL apply -f - <<EOF
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: bgppeer-1
spec:
  node: node1
  peerIP: 172.17.0.6
  asNumber: 64512
  sourceAddress: None
  maxRestartTime: 10s
EOF

    # Expect "graceful restart time 10".
    test_confd_templates sourceaddr_gracefulrestart/step3

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete node node1
    $CALICOCTL delete node node2
}

test_node_mesh_bgp_password() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Create 3 nodes and enable node mesh BGP password
    $CALICOCTL apply -f - <<EOF
kind: BGPConfiguration
apiVersion: projectcalico.org/v3
metadata:
  name: default
spec:
  logSeverityScreen: Info
  nodeToNodeMeshEnabled: true
  nodeMeshPassword:
    secretKeyRef:
      name: my-secrets-1
      key: a
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: IPPool
apiVersion: projectcalico.org/v3
metadata:
  name: ippool-1
spec:
  cidr: 192.168.0.0/16
  ipipMode: Never
  vxlanMode: Never
  natOutgoing: true
---
kind: IPPool
apiVersion: projectcalico.org/v3
metadata:
  name: ippool-2
spec:
  cidr: 2002::/64
  ipipMode: Never
  vxlanMode: Never
  natOutgoing: true
EOF

    # Expect 3 peerings, all with no password because we haven't
    # created the secrets yet.
    test_confd_templates mesh/password/step1

    # Create my-secrets-1 secret with only one of the required keys.
    kubectl create -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-secrets-1
  namespace: kube-system
type: Opaque
stringData:
  a: password-a
EOF

    # Expect the password now on all the peerings using my-secrets-1/a.
    test_confd_templates mesh/password/step2

    # Change the passwords in the other secret.
    kubectl replace -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-secrets-1
  namespace: kube-system
type: Opaque
stringData:
  a: new-password-a
EOF

    # Expect peerings to have new passwords.
    test_confd_templates mesh/password/step3

    # Change the password to an unreferenced key.
    kubectl replace -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: my-secrets-1
  namespace: kube-system
type: Opaque
stringData:
  b: password-b
EOF

    # Expect the password to have disappeared
    test_confd_templates mesh/password/step1

    # Delete a secret.
    kubectl delete secret my-secrets-1 -n kube-system

    # Expect password-a to still be gone.
    test_confd_templates mesh/password/step1

    # Kill confd.
    kill -9 $CONFD_PID

    # Delete remaining resources.
    # Only delete the ippools in KDD mode since calicoctl cannot remove the nodes
    $CALICOCTL delete ippool ippool-1
    $CALICOCTL delete ippool ippool-2
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi

    # Revert BGPConfig changes
    $CALICOCTL apply -f - <<EOF
kind: BGPConfiguration
apiVersion: projectcalico.org/v3
metadata:
  name: default
spec:
EOF

    # Check that passwords were not logged.
    password_logs="`grep 'password-' $LOGPATH/logd1 || true`"
    echo "$password_logs"
    if [ "$password_logs" ]; then
        echo "ERROR: passwords were logged"
        return 1
    fi
}

test_bgp_ttl_security() {
  test_bgp_ttl_security_explicit_node
  test_bgp_ttl_security_peer_selector
  test_bgp_ttl_security_global
}

test_bgp_ttl_security_explicit_node() {

    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and peer them with TTL security
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: ttl-explicit-peer-1
spec:
  node: kube-master
  peerIP: 10.192.0.3
  asNumber: 64517
  ttlSecurity: 1
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: ttl-explicit-peer-2
spec:
  node: kube-master
  peerIP: 10.192.0.4
  asNumber: 64517
  ttlSecurity: 2
EOF

    test_confd_templates ttl_security/explicit_node

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer ttl-explicit-peer-1
    $CALICOCTL delete bgppeer ttl-explicit-peer-2
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_ttl_security_peer_selector() {

    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and peer them using a peer selector with TTL security
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    ttl-security-node: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    ttl-security-node: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: ttl-selector-peers
spec:
  node: kube-master
  peerSelector: has(ttl-security-node)
  ttlSecurity: 1
EOF

    test_confd_templates ttl_security/peer_selector

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer ttl-selector-peers
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_ttl_security_global() {

    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and peer them globally with TTL security
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    ttl-security-node: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    ttl-security-node: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    ttl-security-node: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: ttl-selector-peers
spec:
  peerSelector: has(ttl-security-node)
  ttlSecurity: 1
EOF

    test_confd_templates ttl_security/global

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer ttl-selector-peers
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_ignored_interfaces() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Specify additional interfaces need to be ignored
    $CALICOCTL apply -f - <<EOF
kind: BGPConfiguration
apiVersion: projectcalico.org/v3
metadata:
  name: default
spec:
  logSeverityScreen: Info
  nodeToNodeMeshEnabled: true
  ignoredInterfaces:
  - iface-1
  - iface-2
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
EOF

    test_confd_templates ignored_interfaces

    # Kill confd.
    kill -9 $CONFD_PID

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi
    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_reachable_by() {
  test_bgp_reachable_by_for_global_peers
  test_bgp_reachable_by_for_route_reflectors
}

test_bgp_reachable_by_for_global_peers() {

    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-a-ipv4
spec:
  peerIP: 10.225.0.4
  asNumber: 65515
  reachableBy: 10.224.0.1
  keepOriginalNextHop: true
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-b-ipv4
spec:
  peerIP: 10.225.0.5
  asNumber: 65515
  reachableBy: 10.224.0.1
  keepOriginalNextHop: true
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-a-ipv6
spec:
  peerIP: ffee::10
  asNumber: 65515
  reachableBy: ffee::1:1
  keepOriginalNextHop: true
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-b-ipv6
spec:
  peerIP: ffee::11
  asNumber: 65515
  reachableBy: ffee::1:1
  keepOriginalNextHop: true
EOF

    test_confd_templates reachable_by/global_peers

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer external-route-reflector-a-ipv4
    $CALICOCTL delete bgppeer external-route-reflector-b-ipv4
    $CALICOCTL delete bgppeer external-route-reflector-a-ipv6
    $CALICOCTL delete bgppeer external-route-reflector-b-ipv6

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
        $CALICOCTL delete node kube-master
        $CALICOCTL delete node kube-node-1
        $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_reachable_by_for_route_reflectors() {

    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    route-reflector: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-with-route-reflectors
spec:
  nodeSelector: all()
  peerSelector: route-reflector == 'true'
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-a-ipv4
spec:
  peerIP: 10.225.0.4
  asNumber: 65515
  reachableBy: 10.224.0.1
  keepOriginalNextHop: true
  nodeSelector: route-reflector == 'true'
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-b-ipv4
spec:
  peerIP: 10.225.0.5
  asNumber: 65515
  reachableBy: 10.224.0.1
  keepOriginalNextHop: true
  nodeSelector: route-reflector == 'true'
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-a-ipv6
spec:
  peerIP: ffee::10
  asNumber: 65515
  reachableBy: ffee::1:1
  keepOriginalNextHop: true
  nodeSelector: route-reflector == 'true'
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-b-ipv6
spec:
  peerIP: ffee::11
  asNumber: 65515
  reachableBy: ffee::1:1
  keepOriginalNextHop: true
  nodeSelector: route-reflector == 'true'
EOF

    test_confd_templates reachable_by/route_reflectors

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer peer-with-route-reflectors
    $CALICOCTL delete bgppeer external-route-reflector-a-ipv4
    $CALICOCTL delete bgppeer external-route-reflector-b-ipv4
    $CALICOCTL delete bgppeer external-route-reflector-a-ipv6
    $CALICOCTL delete bgppeer external-route-reflector-b-ipv6

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
        $CALICOCTL delete node kube-master
        $CALICOCTL delete node kube-node-1
        $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_single_bgp_filter_with_global_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.1.0.0/16
    - action: Accept
      interface: "eth0"
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "eth*"
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
    - action: Reject
      interface: "vxlan.calico"
      source: RemotePeers
      matchOperator: In
      cidr: 9000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      interface: "*.calico"
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  peerSelector: has(global-peer)
  filters:
    - test-filter
EOF

    test_confd_templates bgpfilter/single_filter/global_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_single_bgp_filter_with_explicit_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes, 2 BGPFilters, and 2 peerings that each use one of the filters
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-1
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
    - action: Reject
      interface: "eth0"
      source: RemotePeers
      matchOperator: In
      cidr: 77.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      interface: "eth*"
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 9000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "*.calico"
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      interface: "*"
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-2
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.2.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.3.0.0/16
    - action: Accept
      interface: "eth0"
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.2.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.3.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "*.calico"
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000:2::0/64
      interface: "eth*"
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 9000:3::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000:2::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:3::0/64
    - action: Accept
      source: RemotePeers
      interface: "cali*"
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v4
spec:
  node: kube-master
  peerIP: 10.192.0.3
  asNumber: 64517
  filters:
    - test-filter-1
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v6
spec:
  node: kube-master
  peerIP: 2001::103
  asNumber: 64517
  filters:
    - test-filter-1
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v4
spec:
  node: kube-master
  peerIP: 10.192.0.4
  asNumber: 64517
  filters:
    - test-filter-2
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v6
spec:
  node: kube-master
  peerIP: 2001::104
  asNumber: 64517
  filters:
    - test-filter-2
EOF

    test_confd_templates bgpfilter/single_filter/explicit_peer
    # Kill confd.
    kill -9 $CONFD_PID
    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter-1
    $CALICOCTL delete bgpfilter test-filter-2
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v6
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v6
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi
    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_multiple_bgp_filter_with_global_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and 2 BGPFilters then globally pair the nodes all using the same 2 filters
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-1
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "eth0"
  importV4:
    - action: Accept
      interface: "eth*"
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
    - action: Reject
      interface: "vxlan.*"
      source: RemotePeers
      matchOperator: In
      cidr: 9000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      interface: "*.calico"
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-2
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.2.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.3.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.2.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.3.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000:2::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 9000:3::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000:2::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:3::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-multiple-filters
spec:
  peerSelector: has(global-peer)
  filters:
    - test-filter-1
    - test-filter-2
EOF

    test_confd_templates bgpfilter/multi_filter/global_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter-1
    $CALICOCTL delete bgpfilter test-filter-2
    $CALICOCTL delete bgppeer test-global-peer-with-multiple-filters
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_multiple_bgp_filter_with_explicit_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off
    # Create 3 nodes and 2 BGPFilters then pair kube-master with each of the other 2 nodes with each peering using
    # both filters
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-1
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 9000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-2
spec:
  exportV4:
    - action: Accept
      interface: "eth0"
      matchOperator: In
      cidr: 77.2.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.3.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.2.0.0/16
    - action: Reject
      interface: "*"
      source: RemotePeers
      matchOperator: In
      cidr: 44.3.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000:2::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 9000:3::0/64
    - action: Accept
      interface: "*.calico"
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000:2::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:3::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "*"
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-multiple-filters-1-v4
spec:
  peerIP: 10.192.0.3
  asNumber: 64517
  filters:
    - test-filter-1
    - test-filter-2
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-multiple-filters-1-v6
spec:
  peerIP: 2001::103
  asNumber: 64517
  filters:
    - test-filter-1
    - test-filter-2
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-multiple-filters-2-v4
spec:
  peerIP: 10.192.0.4
  asNumber: 64517
  filters:
    - test-filter-1
    - test-filter-2
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-multiple-filters-2-v6
spec:
  peerIP: 2001::104
  asNumber: 64517
  filters:
    - test-filter-1
    - test-filter-2
EOF

    test_confd_templates bgpfilter/multi_filter/explicit_peer
    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter-1
    $CALICOCTL delete bgpfilter test-filter-2
    $CALICOCTL delete bgppeer test-explicit-peer-with-multiple-filters-1-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-multiple-filters-1-v6
    $CALICOCTL delete bgppeer test-explicit-peer-with-multiple-filters-2-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-multiple-filters-2-v6
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_with_node_mesh_enabled() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh on
    turn_mesh_on

    # Create 3 nodes and a BGPFilter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
      interface: "*.calico"
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      interface: "someiface"
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 9000:1::0/64
    - action: Accept
      interface: "some*iface"
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "cali*"
EOF

    test_confd_templates bgpfilter/node_mesh

    # Kill confd.
    kill -9 $CONFD_PID

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_deletion() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 9000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  peerSelector: has(global-peer)
  filters:
    - test-filter
EOF

    test_confd_templates bgpfilter/filter_deletion/step1

    # Now delete the BGPFilter

    $CALICOCTL delete bgpfilter test-filter

    test_confd_templates bgpfilter/filter_deletion/step2
    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_match_operators() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-match-operators
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
    - action: Reject
      matchOperator: NotIn
      cidr: 77.1.0.0/16
    - action: Accept
      matchOperator: Equal
      cidr: 77.2.0.0/16
    - action: Reject
      matchOperator: NotEqual
      cidr: 77.3.0.0/16
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      matchOperator: NotIn
      cidr: 44.1.0.0/16
    - action: Accept
      matchOperator: Equal
      cidr: 44.2.0.0/16
    - action: Reject
      matchOperator: NotEqual
      cidr: 44.3.0.0/16
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000:0::0/64
    - action: Reject
      matchOperator: NotIn
      cidr: 9000:1::0/64
    - action: Accept
      matchOperator: Equal
      cidr: 9000:2::0/64
    - action: Reject
      matchOperator: NotEqual
      cidr: 9000:3::0/64
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000:0::0/64
    - action: Reject
      matchOperator: NotIn
      cidr: 5000:1::0/64
    - action: Accept
      matchOperator: Equal
      cidr: 5000:2::0/64
    - action: Reject
      matchOperator: NotEqual
      cidr: 5000:3::0/64
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  peerSelector: has(global-peer)
  filters:
    - test-filter-match-operators
EOF

    test_confd_templates bgpfilter/match_operators

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter-match-operators
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_match_source() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-match-source
spec:
  exportV4:
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  peerSelector: has(global-peer)
  filters:
    - test-filter-match-source
EOF

    test_confd_templates bgpfilter/match_source

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter-match-source
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_match_interface() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-match-interface
spec:
  exportV4:
    - action: Accept
      interface: "eth0"
      matchOperator: NotIn
      cidr: 77.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "iface"
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
    - action: Reject
      interface: "eth*"
      source: RemotePeers
      matchOperator: NotEqual
      cidr: 9000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      interface: "*.calico"
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  peerSelector: has(global-peer)
  filters:
    - test-filter-match-interface
EOF

    test_confd_templates bgpfilter/match_interface

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter-match-interface
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_names() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter that contains
    # a very long filter name with all possible characters (eg. '.' and '-'). The significance of 45 here is
    # that BIRD symbol names max out at 64 chars, so 45 is the maximum filter name size after subtracting our
    # boilerplate content eg. "bgp_" + "[ex | im]portFilterV[4 | 6]"
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: 45characters.exactly.so.should.not.truncate-1
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
    - action: Reject
      matchOperator: In
      cidr: 77.1.0.0/16
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      matchOperator: In
      cidr: 44.1.0.0/16
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
    - action: Reject
      matchOperator: In
      cidr: 9000:1::0/64
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      matchOperator: In
      cidr: 5000:1::0/64
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: 46characters.exactly.so.should.truncate-123456
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.2.0.0/16
    - action: Reject
      matchOperator: In
      cidr: 77.3.0.0/16
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.2.0.0/16
    - action: Reject
      matchOperator: In
      cidr: 44.3.0.0/16
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000:2::0/64
    - action: Reject
      matchOperator: In
      cidr: 9000:3::0/64
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000:2::0/64
    - action: Reject
      matchOperator: In
      cidr: 5000:3::0/64
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: greater-than-64-characters.so.this.should.definitely.truncate-1234567890
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.4.0.0/16
    - action: Reject
      matchOperator: In
      cidr: 77.5.0.0/16
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.4.0.0/16
    - action: Reject
      matchOperator: In
      cidr: 44.5.0.0/16
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000:4::0/64
    - action: Reject
      matchOperator: In
      cidr: 9000:5::0/64
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000:4::0/64
    - action: Reject
      matchOperator: In
      cidr: 5000:5::0/64
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-truncated-filter-name
spec:
  peerSelector: has(global-peer)
  filters:
    - 45characters.exactly.so.should.not.truncate-1
    - 46characters.exactly.so.should.truncate-123456
    - greater-than-64-characters.so.this.should.definitely.truncate-1234567890
EOF

    test_confd_templates bgpfilter/filter_names/

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter 45characters.exactly.so.should.not.truncate-1
    $CALICOCTL delete bgpfilter 46characters.exactly.so.should.truncate-123456
    $CALICOCTL delete bgpfilter greater-than-64-characters.so.this.should.definitely.truncate-1234567890
    $CALICOCTL delete bgppeer test-global-peer-with-truncated-filter-name
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_import_only_explicit_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes, 2 BGPFilters, and 2 peerings that each use one of the filters
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: import-only-filter-1
spec:
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
      interface: "eth0"
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
      interface: "*"
    - action: Reject
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: import-only-filter-2
spec:
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.2.0.0/16
    - action: Reject
      interface: "vxlan.calico"
      source: RemotePeers
      matchOperator: In
      cidr: 44.3.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000:2::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:3::0/64
    - action: Accept
      interface: "cali*"
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v4
spec:
  node: kube-master
  peerIP: 10.192.0.3
  asNumber: 64517
  filters:
    - import-only-filter-1
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v6
spec:
  node: kube-master
  peerIP: 2001::103
  asNumber: 64517
  filters:
    - import-only-filter-1
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v4
spec:
  node: kube-master
  peerIP: 10.192.0.4
  asNumber: 64517
  filters:
    - import-only-filter-2
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v6
spec:
  node: kube-master
  peerIP: 2001::104
  asNumber: 64517
  filters:
    - import-only-filter-2
EOF

    test_confd_templates bgpfilter/import_only/explicit_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter import-only-filter-1
    $CALICOCTL delete bgpfilter import-only-filter-2
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v6
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v6
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_import_only_global_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: import-only-filter
spec:
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "*"
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      interface: "eth."
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  peerSelector: has(global-peer)
  filters:
    - import-only-filter
EOF

    test_confd_templates bgpfilter/import_only/global_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter import-only-filter
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_export_only_explicit_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes, 2 BGPFilters, and 2 peerings that each use one of the filters
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: export-only-filter-1
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      interface: "*.calico"
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      interface: "*"
      source: RemotePeers
    - action: Reject
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: export-only-filter-2
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 44.2.0.0/16
    - action: Reject
      interface: "eth9"
      source: RemotePeers
      matchOperator: In
      cidr: 44.3.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 5000:2::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:3::0/64
    - action: Accept
      interface: "*.calico"
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v4
spec:
  node: kube-master
  peerIP: 10.192.0.3
  asNumber: 64517
  filters:
    - export-only-filter-1
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v6
spec:
  node: kube-master
  peerIP: 2001::103
  asNumber: 64517
  filters:
    - export-only-filter-1
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v4
spec:
  node: kube-master
  peerIP: 10.192.0.4
  asNumber: 64517
  filters:
    - export-only-filter-2
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v6
spec:
  node: kube-master
  peerIP: 2001::104
  asNumber: 64517
  filters:
    - export-only-filter-2
EOF

    test_confd_templates bgpfilter/export_only/explicit_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter export-only-filter-1
    $CALICOCTL delete bgpfilter export-only-filter-2
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v6
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v6
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_export_only_global_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: export-only-filter
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "*.calico"
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      interface: "*.calico"
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  peerSelector: has(global-peer)
  filters:
    - export-only-filter
EOF

    test_confd_templates bgpfilter/export_only/global_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter export-only-filter
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_v4_only_explicit_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes, 2 BGPFilters, and 2 peerings that each use one of the filters
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-1
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "*.calico"
  importV4:
    - action: Accept
      interface: ".calico"
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-2
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.2.0.0/16
    - action: Reject
      interface: "random.iface"
      source: RemotePeers
      matchOperator: In
      cidr: 77.3.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.2.0.0/16
    - action: Reject
      source: RemotePeers
      interface: "random*"
      matchOperator: In
      cidr: 44.3.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v4
spec:
  node: kube-master
  peerIP: 10.192.0.3
  asNumber: 64517
  filters:
    - test-filter-1
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v6
spec:
  node: kube-master
  peerIP: 2001::103
  asNumber: 64517
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v4
spec:
  node: kube-master
  peerIP: 10.192.0.4
  asNumber: 64517
  filters:
    - test-filter-2
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v6
spec:
  node: kube-master
  peerIP: 2001::104
  asNumber: 64517
EOF

    test_confd_templates bgpfilter/v4_only/explicit_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter-1
    $CALICOCTL delete bgpfilter test-filter-2
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v6
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v6
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_v4_only_global_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter
spec:
  exportV4:
    - action: Accept
      matchOperator: In
      cidr: 77.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 77.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 44.1.0.0/16
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  peerSelector: has(global-peer)
  filters:
    - test-filter
EOF

    test_confd_templates bgpfilter/v4_only/global_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_v6_only_explicit_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes, 2 BGPFilters, and 2 peerings that each use one of the filters
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-1
spec:
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
      interface: "eth0"
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 9000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "eth*"
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "*"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter-2
spec:
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000:2::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 9000:3::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000:2::0/64
    - action: Reject
      interface: "eth*"
      source: RemotePeers
      matchOperator: In
      cidr: 5000:3::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v4
spec:
  node: kube-master
  peerIP: 10.192.0.3
  asNumber: 64517
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-1-v6
spec:
  node: kube-master
  peerIP: 2001::103
  asNumber: 64517
  filters:
    - test-filter-1
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v4
spec:
  node: kube-master
  peerIP: 10.192.0.4
  asNumber: 64517
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-explicit-peer-with-filter-2-v6
spec:
  node: kube-master
  peerIP: 2001::104
  asNumber: 64517
  filters:
    - test-filter-2
EOF

    test_confd_templates bgpfilter/v6_only/explicit_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter-1
    $CALICOCTL delete bgpfilter test-filter-2
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-1-v6
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v4
    $CALICOCTL delete bgppeer test-explicit-peer-with-filter-2-v6
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filter_v6_only_global_peers() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: test-filter
spec:
  exportV6:
    - action: Accept
      matchOperator: In
      cidr: 9000::0/64
    - action: Reject
      interface: "*.calico"
      source: RemotePeers
      matchOperator: In
      cidr: 9000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
    - action: Reject
      source: RemotePeers
      matchOperator: In
      cidr: 5000:1::0/64
    - action: Accept
      source: RemotePeers
    - action: Reject
      interface: "eth0"
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  peerSelector: has(global-peer)
  filters:
    - test-filter
EOF

    test_confd_templates bgpfilter/v6_only/global_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter test-filter
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_filters() {
  test_single_bgp_filter_with_global_peers
  test_single_bgp_filter_with_explicit_peers
  test_multiple_bgp_filter_with_global_peers
  test_multiple_bgp_filter_with_explicit_peers
  test_bgp_filter_with_node_mesh_enabled
  test_bgp_filter_deletion
  test_bgp_filter_names
  test_bgp_filter_match_operators
  test_bgp_filter_match_source
  test_bgp_filter_match_interface
  test_bgp_filter_import_only_explicit_peers
  test_bgp_filter_import_only_global_peers
  test_bgp_filter_export_only_explicit_peers
  test_bgp_filter_export_only_global_peers
  test_bgp_filter_v4_only_explicit_peers
  test_bgp_filter_v4_only_global_peers
  test_bgp_filter_v6_only_explicit_peers
  test_bgp_filter_v6_only_global_peers
}

test_bgp_local_bgp_peer() {
    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -rf /etc/calico/confd/endpoint-status || true
        rm -f /etc/calico/confd/config/*
    fi

    mkdir -p /etc/calico/confd/endpoint-status
    cat <<EOF > /etc/calico/confd/endpoint-status/pod1
{"ifaceName":"cali97e1defe654","ipv4Nets":["192.168.162.134/32"],"ipv6Nets":["fd00:10:244:0:586d:4461:e980:a284/128"],"bgpPeerName":"test-global-peer-with-filter"}
EOF
cat <<EOF > /etc/calico/confd/endpoint-status/pod2
{"ifaceName":"cali97e1defe656","ipv4Nets":["192.168.162.136/32"],"ipv6Nets":["fd00:10:244:0:586d:4461:e980:a286/128"],"bgpPeerName":"test-node-peer-with-filter"}
EOF

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" CALICO_ENDPOINT_STATUS_PATH_PREFIX="/etc/calico/confd" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    # Create 3 nodes and a BGPFilter then globally pair the nodes all using the same filter
    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
  labels:
    global-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
  labels:
    node-peer: yes
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
kind: BGPFilter
apiVersion: projectcalico.org/v3
metadata:
  name: import-only-filter
spec:
  importV4:
    - action: Accept
      matchOperator: In
      cidr: 44.0.0.0/16
  importV6:
    - action: Accept
      matchOperator: In
      cidr: 5000::0/64
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-global-peer-with-filter
spec:
  localWorkloadSelector: app == 'calico-bird-0'
  asNumber: 64516
  localASNumber: 65002
  filters:
    - import-only-filter
---
kind: BGPPeer
apiVersion: projectcalico.org/v3
metadata:
  name: test-node-peer-with-filter
spec:
  localWorkloadSelector: app == 'calico-bird-0'
  node: kube-master
  asNumber: 64517
  localASNumber: 65001
  filters:
    - import-only-filter
EOF

    test_confd_templates explicit_peering/local_bgp_peer

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgpfilter import-only-filter
    $CALICOCTL delete bgppeer test-global-peer-with-filter
    $CALICOCTL delete bgppeer test-node-peer-with-filter
    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
      $CALICOCTL delete node kube-master
      $CALICOCTL delete node kube-node-1
      $CALICOCTL delete node kube-node-2
    fi

    rm -r /etc/calico/confd/endpoint-status

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_next_hop_mode() {
  test_bgp_next_hop_mode_for_global_peers
  test_bgp_next_hop_mode_for_route_reflectors
}

test_bgp_next_hop_mode_for_global_peers() {

    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-a-ipv4
spec:
  peerIP: 10.225.0.4
  asNumber: 65515
  nextHopMode: Keep
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-b-ipv4
spec:
  peerIP: 10.225.0.5
  asNumber: 64512    # iBGP peer
  nextHopMode: Self  # next hop self for an iBGP peer
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-a-ipv6
spec:
  peerIP: ffee::10
  asNumber: 65515
  nextHopMode: Keep
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-b-ipv6
spec:
  peerIP: ffee::11
  asNumber: 64512
  nextHopMode: Self
EOF

    test_confd_templates next_hop_mode/global_peers

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer external-route-reflector-a-ipv4
    $CALICOCTL delete bgppeer external-route-reflector-b-ipv4
    $CALICOCTL delete bgppeer external-route-reflector-a-ipv6
    $CALICOCTL delete bgppeer external-route-reflector-b-ipv6

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
        $CALICOCTL delete node kube-master
        $CALICOCTL delete node kube-node-1
        $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_next_hop_mode_for_route_reflectors() {

    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    route-reflector: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-with-route-reflectors
spec:
  nodeSelector: all()
  peerSelector: route-reflector == 'true'
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-a-ipv4
spec:
  peerIP: 10.225.0.4
  asNumber: 65515
  nextHopMode: Keep
  nodeSelector: route-reflector == 'true'
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-b-ipv4
spec:
  peerIP: 10.225.0.5
  asNumber: 64512    # iBGP peer
  nextHopMode: Self  # next hop self for an iBGP peer
  nodeSelector: route-reflector == 'true'
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-a-ipv6
spec:
  peerIP: ffee::10
  asNumber: 65515
  nextHopMode: Keep
  nodeSelector: route-reflector == 'true'
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: external-route-reflector-b-ipv6
spec:
  peerIP: ffee::11
  asNumber: 64512
  nextHopMode: Self
  nodeSelector: route-reflector == 'true'
EOF

    test_confd_templates next_hop_mode/route_reflectors

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer peer-with-route-reflectors
    $CALICOCTL delete bgppeer external-route-reflector-a-ipv4
    $CALICOCTL delete bgppeer external-route-reflector-b-ipv4
    $CALICOCTL delete bgppeer external-route-reflector-a-ipv6
    $CALICOCTL delete bgppeer external-route-reflector-b-ipv6

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
        $CALICOCTL delete node kube-master
        $CALICOCTL delete node kube-node-1
        $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_reverse_peering() {
  test_bgp_reverse_peering_manual
  test_bgp_reverse_peering_auto
}

test_bgp_reverse_peering_manual() {

    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    route-reflector: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-with-route-reflectors
spec:
  nodeSelector: all()
  peerSelector: route-reflector == 'true'
  reversePeering: Manual
EOF

    test_confd_templates reverse_peering/manual

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer peer-with-route-reflectors

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
        $CALICOCTL delete node kube-master
        $CALICOCTL delete node kube-node-1
        $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}

test_bgp_reverse_peering_auto() {

    # For KDD, run Typha and clean up the output directory.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        start_typha
        rm -f /etc/calico/confd/config/*
    fi

    # Run confd as a background process.
    echo "Running confd as background process"
    NODENAME=kube-master BGP_LOGSEVERITYSCREEN="debug" confd -confdir=/etc/calico/confd >$LOGPATH/logd1 2>&1 &
    CONFD_PID=$!
    echo "Running with PID " $CONFD_PID

    # Turn the node-mesh off
    turn_mesh_off

    $CALICOCTL apply -f - <<EOF
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-master
  labels:
    route-reflector: yes
spec:
  bgp:
    ipv4Address: 10.192.0.2/16
    ipv6Address: "2001::103/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-1
spec:
  bgp:
    ipv4Address: 10.192.0.3/16
    ipv6Address: "2001::102/64"
---
kind: Node
apiVersion: projectcalico.org/v3
metadata:
  name: kube-node-2
spec:
  bgp:
    ipv4Address: 10.192.0.4/16
    ipv6Address: "2001::104/64"
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: peer-with-route-reflectors
spec:
  nodeSelector: all()
  peerSelector: route-reflector == 'true'
  reversePeering: Auto
EOF

    test_confd_templates reverse_peering/auto

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    $CALICOCTL delete bgppeer peer-with-route-reflectors

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
        $CALICOCTL delete node kube-master
        $CALICOCTL delete node kube-node-1
        $CALICOCTL delete node kube-node-2
    fi

    # For KDD, kill Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
        kill_typha
    fi
}


