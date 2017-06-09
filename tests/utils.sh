#!/bin/sh

get_templates() {
    echo "Getting latest confd templates from calicoctl repo"
    git clone https://github.com/projectcalico/calicoctl.git /calicoctl
    ln -s /calicoctl/calico_node/filesystem/etc/calico/ /etc/calico

    echo "Building initial toml files"
    # This is pulled from the calico_node rc.local script, it generates these three
    # toml files populated with the $NODENAME var.
    sed "s/NODENAME/$NODENAME/" /etc/calico/confd/templates/bird6_aggr.toml.template > /etc/calico/confd/conf.d/bird6_aggr.toml
    sed "s/NODENAME/$NODENAME/" /etc/calico/confd/templates/bird_aggr.toml.template > /etc/calico/confd/conf.d/bird_aggr.toml
    sed "s/NODENAME/$NODENAME/" /etc/calico/confd/templates/bird_ipam.toml.template > /etc/calico/confd/conf.d/bird_ipam.toml

    # Need to pause as running confd immediately after might result in files not being present.
    sync
}

test_templates() {
    ret_code=0

    # Check the generated templates against known compiled templates.
    for f in `ls /tests/compiled_templates`; do
    echo "Comparing $f"
    if  ! diff -q /tests/compiled_templates/$f /etc/calico/confd/config/$f; then
        echo "${f} templates do not match, showing diff of expected vs received"
        diff /tests/compiled_templates/$f /etc/calico/confd/config/$f
        ret_code=1
    fi
    done

    return $ret_code
}
