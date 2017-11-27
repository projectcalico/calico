#!/bin/bash

# This is a set of utility functions for common code when
# testing confd templates

# Populates etcd with mock data
# $1 would be the tests you want to run e.g. mesh/global
populate_etcd() {
    to_test=$1

    echo "Populating etcd with test data"
    # The empty data needs to be eval'd with the entire command else we end up with ""
    # instead of empty values for these keys.
    while read cmd; do
      eval $cmd > /dev/null 2>&1
    done < /tests/mock_data/etcd/${to_test}/etcd_empty_data

    # We set a bunch of data used to populate the templates.
    while read data; do
      etcdctl set $data > /dev/null 2>&1
    done < /tests/mock_data/etcd/${to_test}/etcd_data

    # Some directories that are required to exist for the templates.
    while read dir; do
      etcdctl mkdir $dir > /dev/null 2>&1
    done < /tests/mock_data/etcd/${to_test}/etcd_dirs
}

clean_etcd() {
    echo "Cleaning out etcd"
    etcdctl rm -r /calico
}

# Populates the k8s API server with mock data
# $1 would be the tests you want to run e.g. mesh/global
populate_kdd() {
    to_test=$1

    echo "Creating CRDs and dummy Nodes"
    # This will create the dummy nodes and the custom resource definitions we can populate
    local i=0
    until kubectl apply -f /tests/mock_data/kdd/${to_test}/crds.yaml; do
	i=$(($i+1))
	[ $i -gt 30 ] && echo ERROR: The API server failed to come online after $i seconds. && exit 1
	echo "Waiting for API server to come online"
	sleep 1
    done

    kubectl apply -f /tests/mock_data/kdd/${to_test}/nodes.yaml 
    [ $? -ne 0 ] && ERROR: kubectl apply failed. && exit 1

    echo "Waiting for CRDs to apply"
    # There is a delay when creating the CRDs and them being ready for use, so we
    # try to apply the data until it finally makes it into the API server
    i=0
    until kubectl apply -f /tests/mock_data/kdd/${to_test}/crd_data.yaml; do
      i=$(($i+1))
      [ $i -gt 30 ] && echo ERROR: kubectl apply failed after $i tries. && exit 1
      sleep 1
    done
}

clean_kdd() {
    echo "Cleaning out k8s API"
    to_remove=$1
    kubectl delete -f /tests/mock_data/kdd/${to_remove}/crd_data.yaml > /dev/null 2>&1
    kubectl delete -f /tests/mock_data/kdd/${to_remove}/crds.yaml > /dev/null 2>&1
    kubectl delete -f /tests/mock_data/kdd/${to_remove}/nodes.yaml > /dev/null 2>&1
}

# get_templates attempts to grab the latest templates from the calico repo
get_templates() {
    repo_dir="/node-repo"
    if [ ! -d ${repo_dir} ]; then
        echo "Getting latest confd templates from calico repo"
        git clone https://github.com/projectcalico/calico.git --branch=v2.6.x-series ${repo_dir}
        ln -s ${repo_dir}/calico_node/filesystem/etc/calico/ /etc/calico
    fi
}

create_tomls() {
    echo "Building initial toml files"
    # This is pulled from the calico_node rc.local script, it generates these three
    # toml files populated with the $NODENAME var set in calling script.
    sed "s/NODENAME/$NODENAME/" /etc/calico/confd/templates/bird6_aggr.toml.template > /etc/calico/confd/conf.d/bird6_aggr.toml
    sed "s/NODENAME/$NODENAME/" /etc/calico/confd/templates/bird_aggr.toml.template > /etc/calico/confd/conf.d/bird_aggr.toml
    sed "s/NODENAME/$NODENAME/" /etc/calico/confd/templates/bird_ipam.toml.template > /etc/calico/confd/conf.d/bird_ipam.toml

    # Need to pause as running confd immediately after might result in files not being present.
    sync
}

# Compares the generated templates against the known good templates
# $1 would be the tests you want to run e.g. mesh/global
test_templates() {
    to_test=$1
    ret_code=0

    # Check the generated templates against known compiled templates.
    for f in `ls /tests/compiled_templates/${to_test}`; do
    echo "Comparing $f"
    if ! diff -q /tests/compiled_templates/${to_test}/${f} /etc/calico/confd/config/${f}; then
        echo "$f templates do not match, showing diff of expected vs received"
        diff /tests/compiled_templates/${to_test}/${f} /etc/calico/confd/config/${f}
        ret_code=1
    fi
    done

    # Wipe the templates we compiled here as to not leak them into other tests
    rm /etc/calico/confd/config/*.cfg

    return ${ret_code}
}
