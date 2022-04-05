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
    fi

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
        run_extra_test test_node_mesh_bgp_password
        run_extra_test test_bgp_password
        run_extra_test test_bgp_sourceaddr_gracefulrestart
        run_extra_test test_node_deletion
        run_extra_test test_idle_peers
        run_extra_test test_router_id_hash
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
    kubectl apply -f - <<EOF
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
    kubectl apply -f - <<EOF
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
    kubectl apply -f - <<EOF
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
    kubectl apply -f - <<EOF
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
    if [ "$password_logs"  ]; then
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
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/os: linux
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
        echo "Copying nodes to ${LOGPATH}/nodes.yaml"
        $CALICOCTL get nodes -o yaml > ${LOGPATH}/nodes.yaml
        echo "Copying bgp config to ${LOGPATH}/bgpconfig.yaml"
        $CALICOCTL get bgpconfigs -o yaml > ${LOGPATH}/bgpconfig.yaml
        echo "Copying bgp peers to ${LOGPATH}/bgppeers.yaml"
        $CALICOCTL get bgppeers -o yaml > ${LOGPATH}/bgppeers.yaml
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
    kubectl apply -f - <<EOF
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
    kubectl apply -f - <<EOF
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
    if [ "$password_logs"  ]; then
        echo "ERROR: passwords were logged"
        return 1
    fi
}
