#!/bin/bash

trap 'echo "\nCaught signal, exiting...\n"; exit 1' SIGINT SIGTERM

: ${UPDATE_EXPECTED_DATA:=false}

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
        run_extra_test test_bgp_password_deadlock
    fi

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
        run_extra_test test_bgp_password
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
    calicoctl apply -f - <<EOF
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
    calicoctl delete node node1
    calicoctl delete node node2
    calicoctl delete node node3
    calicoctl delete node node4
    calicoctl delete bgppeer bgppeer-1
    calicoctl delete bgppeer bgppeer-2

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
        calicoctl apply -f - <<EOF
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
        calicoctl delete bgppeer bgppeer-$ii
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
    calicoctl apply -f - <<EOF
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
    calicoctl delete node node3

    # Expect just 2 peerings.
    expect_peerings 2

    # Kill confd.
    kill -9 $CONFD_PID

    # Turn the node-mesh back on.
    turn_mesh_on

    # Delete remaining resources.
    calicoctl delete node node1
    calicoctl delete node node2
    calicoctl delete node node4
    calicoctl delete bgppeer bgppeer-1
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
    calicoctl apply -f - <<EOF
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
        calicoctl apply -f - <<EOF
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
    calicoctl delete node node1
    calicoctl delete node node2
    calicoctl delete bgppeer global
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
        run_individual_test 'mesh/ipip-always'
        run_individual_test 'mesh/ipip-cross-subnet'
        run_individual_test 'mesh/ipip-off'
        run_individual_test 'mesh/static-routes'
        run_individual_test 'mesh/communities'
    done

    # Turn the node-mesh off.
    turn_mesh_off

    # Run the explicit peering tests.
    for i in $(seq 1 2); do
        run_individual_test 'explicit_peering/global'
        run_individual_test 'explicit_peering/specific_node'
        run_individual_test 'explicit_peering/selectors'
        run_individual_test 'explicit_peering/route_reflector'
        run_individual_test 'explicit_peering/keepnexthop'
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
        run_individual_test_oneshot 'mesh/ipip-always'
        run_individual_test_oneshot 'mesh/ipip-cross-subnet'
        run_individual_test_oneshot 'mesh/ipip-off'
        run_individual_test_oneshot 'mesh/vxlan-always'
        run_individual_test_oneshot 'explicit_peering/global'
        run_individual_test_oneshot 'explicit_peering/specific_node'
        run_individual_test_oneshot 'explicit_peering/selectors'
        run_individual_test_oneshot 'explicit_peering/route_reflector'
        run_individual_test_oneshot 'mesh/static-routes'
        run_individual_test_oneshot 'mesh/communities'
        run_individual_test_oneshot 'explicit_peering/keepnexthop'
        export CALICO_ROUTER_ID=10.10.10.10
        run_individual_test_oneshot 'mesh/static-routes-no-ipv4-address'
        export -n CALICO_ROUTER_ID
        unset CALICO_ROUTER_ID
    done
}


# Turn the node-to-node mesh off.
turn_mesh_off() {
    calicoctl apply -f - <<EOF
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
    calicoctl apply -f - <<EOF
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
    calicoctl apply -f /tests/mock_data/calicoctl/${testdir}/input.yaml

    # Populate Kubernetes API with data if it exists for this test.
    if [[ -f /tests/mock_data/calicoctl/${testdir}/kubectl-input.yaml ]]; then
            KUBECONFIG=/tests/confd_kubeconfig kubectl apply -f /tests/mock_data/calicoctl/${testdir}/kubectl-input.yaml
    fi

    # Check the confd templates are updated.
    test_confd_templates $testdir

    if [ -f /tests/mock_data/calicoctl/${testdir}/step2/input.yaml ]; then
        echo "Config changes for step 2"
        calicoctl apply -f /tests/mock_data/calicoctl/${testdir}/step2/input.yaml

        # Check config changes as expected.
        test_confd_templates ${testdir}/step2

        # That changes testdir, so undo that change.
        testdir=$testdir_save
    fi

    # Remove any resource that does not need to be persisted due to test environment
    # limitations.
    echo "Preparing Calico data for next test"
    if [[ -f /tests/mock_data/calicoctl/${testdir}/kubectl-delete.yaml ]]; then
            KUBECONFIG=/tests/confd_kubeconfig kubectl delete -f /tests/mock_data/calicoctl/${testdir}/kubectl-delete.yaml
    fi

    if [ -f /tests/mock_data/calicoctl/${testdir}/step2/delete.yaml ]; then
        calicoctl delete -f /tests/mock_data/calicoctl/${testdir}/step2/delete.yaml
    fi
    calicoctl delete -f /tests/mock_data/calicoctl/${testdir}/delete.yaml
}

# Run an individual test using oneshot mode:
# - applying a set of resources using calicoctl
# - run confd in oneshot mode
# - verify the templates generated by confd as a result.
run_individual_test_oneshot() {
    testdir=$1

    # Populate Calico using calicoctl to load the input.yaml test data.
    echo "Populating calico with test data using calicoctl: " $testdir
    calicoctl apply -f /tests/mock_data/calicoctl/${testdir}/input.yaml

    # Populate Kubernetes API with data if it exists for this test.
    if [[ -f /tests/mock_data/calicoctl/${testdir}/kubectl-input.yaml ]]; then
            KUBECONFIG=/tests/confd_kubeconfig kubectl apply -f /tests/mock_data/calicoctl/${testdir}/kubectl-input.yaml
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
            KUBECONFIG=/tests/confd_kubeconfig kubectl delete -f /tests/mock_data/calicoctl/${testdir}/kubectl-delete.yaml
    fi
    calicoctl delete -f /tests/mock_data/calicoctl/${testdir}/delete.yaml
}

start_typha() {
    echo "Starting Typha"
    TYPHA_DATASTORETYPE=kubernetes \
        KUBECONFIG=/tests/confd_kubeconfig \
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

        # Order of line in templates is not guaranteed for communities test, so sort and compare
        if [[ $(diff --ignore-blank-lines -q ${expected} ${actual}) != "" ]] \
          && [[ "${testdir}" != *"mesh/communities"* || $(diff <(sort ${expected}) <(sort ${actual})) != "" ]] ; then
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
        calicoctl get nodes -o yaml > ${LOGPATH}/nodes.yaml
        echo "Copying bgp config to ${LOGPATH}/bgpconfig.yaml"
        calicoctl get bgpconfigs -o yaml > ${LOGPATH}/bgpconfig.yaml
        echo "Copying bgp peers to ${LOGPATH}/bgppeers.yaml"
        calicoctl get bgppeers -o yaml > ${LOGPATH}/bgppeers.yaml
        echo "Copying ip pools to ${LOGPATH}/ippools.yaml"
        calicoctl get ippools -o yaml > ${LOGPATH}/ippools.yaml
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
