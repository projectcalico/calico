#!/bin/sh

# Set the ENV var for KDD backend
export DATASTORE_TYPE=kubernetes

# Create the CRDs by applying the crds.yaml manifest.
echo "Creating Calico CRDs..."
/sbin/kubectl apply -f crds.yaml

# Get IPPools list with old calicoctl (from TPR) and save it as a yaml file.
# Apply the yaml file with the new calicoctl (to CRD)
echo "Migrating IPPools..."
/sbin/calicoctl-v1.4 get ippool -o yaml > ippool.yaml
retval=$?
if [ $retval == 0 ];
then
    echo "Successfully got the Global BGP Peers:"
    cat ippool.yaml
    /sbin/calicoctl-v1.5 apply -f ippool.yaml
fi

# Get BGPPeers list with old calicoctl (from TPR) and save it as a yaml file.
# Apply the yaml file with the new calicoctl (to CRD)
echo "Migrating BGPPeers..."
/sbin/calicoctl-v1.4 get globalbgppeer -o yaml > bgppeer.yaml
retval=$?
if [ $retval == 0 ];
then
    echo "Successfully got the Global BGP Peers:"
    cat bgppeer.yaml
    /sbin/calicoctl-v1.5 apply -f bgppeer.yaml
fi


# List all the Felix configs using kubectl and save it in a yaml file.
# Change the apiVersion from 'projectcalico.org/v1' to 'crd.projectcalico.org/v1',
# rename resource kind from 'GlobalConfig' to 'GlobalFelixConfig' and save it in a new yaml file.
# Apply the modified yaml file.
echo "Migrating GlobalFelixConfig..."
/sbin/kubectl get globalconfig --all-namespaces -o yaml > cat tpr-felixconfig.yaml
retval=$?
if [ $retval == 0 ];
then
    echo "Successfully got the Felix Config:"
    cat tpr-felixconfig.yaml
    cat tpr-felixconfig.yaml | sed '/apiVersion/s/projectcalico\.org\/v1/crd\.projectcalico\.org\/v1/g' | sed '/kind/s/GlobalConfig/GlobalFelixConfig/g' > crd-felixconfig.yaml
    echo "Successfully renamed the resource kind"
    cat crd-felixconfig.yaml
    -/sbin/kubectl apply -f crd-felixconfig.yaml
fi


# List all the BGP configs using kubectl and save it in a yaml file.
# Change the apiVersion from 'projectcalico.org/v1' to 'crd.projectcalico.org/v1' and save it in a new yaml file.
# Apply the modified yaml file.
echo "Migrating GlobalBGPConfig..."
/sbin/kubectl get globalbgpconfig --all-namespaces -o yaml > tpr-bgpconfig.yaml
retval=$?
if [ $retval == 0 ];
then
    echo "Successfully got the BGP Config:"
    cat tpr-bgpconfig.yaml
    cat tpr-bgpconfig.yaml | sed '/apiVersion/s/projectcalico\.org\/v1/crd\.projectcalico\.org\/v1/g' > crd-bgpconfig.yaml
    echo "Successfully renames the resource kind"
    cat crd-bgpconfig.yaml
    -/sbin/kubectl apply -f crd-bgpconfig.yaml
fi


# Delete the TPRs manually once you confirm everything is working fine after the upgrade.
