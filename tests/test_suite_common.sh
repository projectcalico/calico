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

    if [ "$DATASTORE_TYPE" = etcdv3 ]; then
	test_node_deletion
	test_idle_peers
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
    for i in $(seq 1 5); do
        execute_tests_daemon
    done
    echo "Daemon-mode tests passed"
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
    for i in $(seq 1 5); do
        run_individual_test 'mesh/ipip-always'
        run_individual_test 'mesh/ipip-cross-subnet'
        run_individual_test 'mesh/ipip-off'
    done

    # Turn the node-mesh off.
    turn_mesh_off

    # Run the explicit peering tests.
    for i in $(seq 1 5); do
        run_individual_test 'explicit_peering/global'
        run_individual_test 'explicit_peering/specific_node'
        run_individual_test 'explicit_peering/selectors'
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
        run_individual_test_oneshot 'explicit_peering/global'
        run_individual_test_oneshot 'explicit_peering/specific_node'
        run_individual_test_oneshot 'explicit_peering/selectors'
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

    # Populate Calico using calicoctl to load the input.yaml test data.
    echo "Populating calico with test data using calicoctl: " $testdir
    calicoctl apply -f /tests/mock_data/calicoctl/${testdir}/input.yaml

    # Check the confd templates are updated.
    test_confd_templates $testdir

    # Remove any resource that does not need to be persisted due to test environment
    # limitations.
    echo "Preparing Calico data for next test"
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

    # For KDD, run Typha.
    if [ "$DATASTORE_TYPE" = kubernetes ]; then
	start_typha
    fi

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
    calicoctl delete -f /tests/mock_data/calicoctl/${testdir}/delete.yaml
}

start_typha() {
    echo "Starting Typha"
    TYPHA_DATASTORETYPE=kubernetes \
        KUBECONFIG=/tests/confd_kubeconfig \
        TYPHA_LOGSEVERITYSCREEN=debug \
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
    for f in `ls /tests/compiled_templates/${DATASTORE_TYPE}/${testdir}`; do
        expected=/tests/compiled_templates/${DATASTORE_TYPE}/${testdir}/${f}
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
