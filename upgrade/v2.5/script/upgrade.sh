#!/bin/sh

# Set the ENV var for KDD backend
export DATASTORE_TYPE=kubernetes

# Create the CRDs by applying the crds.yaml manifest.
echo "Creating Calico CRDs..."; echo
/sbin/kubectl apply -f crds.yaml

# Get IPPools list with old calicoctl (from TPR) and save it as a yaml file.
# Apply the yaml file with the new calicoctl (to CRD)
echo "Migrating IPPools..."
/sbin/calicoctl-v1.4 get ippool -o yaml > ippool.yaml
retval=$?
if [ $retval == 0 ]; then
    if [ -f ippool.yaml ]; then
        echo "Successfully got the IPPools:"
        cat ippool.yaml
        lines=`cat ippool.yaml | wc -l`
        cat ippool.yaml | grep '\[\]'
        retval=$?
        if [ $retval == 0 -a $lines == 1 ]; then
            echo "No IPPools found to migrate."
        else
            /sbin/calicoctl-v1.5 apply -f ippool.yaml
        fi
    else
       echo "No IPPools found to migrate."
    fi
else
    echo "Failed to get IPPools"
fi

# Get BGPPeers list with old calicoctl (from TPR) and save it as a yaml file.
# Apply the yaml file with the new calicoctl (to CRD)
echo; echo "Migrating BGPPeers..."
/sbin/calicoctl-v1.4 get bgppeer -o yaml > bgppeer.yaml
retval=$?
if [ $retval == 0 ]; then
    if [ -f bgppeer.yaml ]; then
        echo "Successfully got the Global BGP Peers:"
        cat bgppeer.yaml
        lines=`cat bgppeer.yaml | wc -l`
        cat bgppeer.yaml | grep '\[\]'
        retval=$?
        if [ $retval == 0 -a $lines == 1 ]; then
            echo "No BGPPeers found to migrate."
        else
            /sbin/calicoctl-v1.5 apply -f bgppeer.yaml
        fi
    else
       echo "No BGPPeers found to migrate."
    fi
else
    echo "Failed to get Global BGP Peers"
fi


# List all the Felix configs using kubectl and save it in a yaml file.
# Change the apiVersion from 'projectcalico.org/v1' to 'crd.projectcalico.org/v1',
# rename resource kind from 'GlobalConfig' to 'GlobalFelixConfig' and save it in a new yaml file.
# Apply the modified yaml file.
echo; echo "Migrating GlobalFelixConfig..."
/sbin/kubectl get globalconfig --all-namespaces -o yaml > tpr-felixconfig.yaml
retval=$?
if [ $retval == 0 ]; then
    if [ -f tpr-felixconfig.yaml ]; then
        echo "Successfully got the Felix Config:"
        cat tpr-felixconfig.yaml
        cat tpr-felixconfig.yaml | grep 'items\: \[\]'
        retval=$?
        if [ $retval == 0 ]; then
            echo "No GlobalFelixConfig found to migrate."
        else
            cat tpr-felixconfig.yaml | sed '/apiVersion/s/projectcalico\.org\/v1/crd\.projectcalico\.org\/v1/g' | sed '/kind/s/GlobalConfig/GlobalFelixConfig/g' > crd-felixconfig.yaml
            echo "Successfully renamed the resource kind"
            cat crd-felixconfig.yaml
            /sbin/kubectl apply -f crd-felixconfig.yaml
        fi
    else
       echo "No GlobalFelixConfig found to migrate."
    fi
else
    echo "Failed to get Global Felix config"
fi


# List all the BGP configs using kubectl and save it in a yaml file.
# Change the apiVersion from 'projectcalico.org/v1' to 'crd.projectcalico.org/v1' and save it in a new yaml file.
# Apply the modified yaml file.
echo; echo "Migrating GlobalBGPConfig..."
/sbin/kubectl get globalbgpconfig --all-namespaces -o yaml > tpr-bgpconfig.yaml
retval=$?
if [ $retval == 0 ]; then
    if [ -f tpr-bgpconfig.yaml ]; then
        echo "Successfully got the BGP Config:"
        cat tpr-bgpconfig.yaml
        cat tpr-bgpconfig.yaml | grep 'items\: \[\]'
        retval=$?
        if [ $retval == 0 ]; then
            echo "No GlobalBGPConfig found to migrate."
        else
            cat tpr-bgpconfig.yaml | sed '/apiVersion/s/projectcalico\.org\/v1/crd\.projectcalico\.org\/v1/g' > crd-bgpconfig.yaml
            echo "Successfully renamed the resource kind"
            cat crd-bgpconfig.yaml
            /sbin/kubectl apply -f crd-bgpconfig.yaml
        fi
    else
       echo "No GlobalBGPConfig found to migrate."
    fi
else
    echo "Failed to get BGP config"
fi