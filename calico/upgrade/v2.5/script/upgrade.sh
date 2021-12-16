#!/bin/sh

# Set the ENV var for KDD backend
export DATASTORE_TYPE=kubernetes

# Create the CRDs by applying the crds.yaml manifest.
echo "Creating Calico CRDs..."; echo
/sbin/kubectl apply -f crds.yaml
# Applying TPRs with trps.yaml manifest.
/sbin/kubectl apply -f tprs.yaml

# Get IPPools list with old calicoctl (from TPR) and save it as a yaml file.
# Apply the yaml file with the new calicoctl (to CRD)
echo "Migrating IPPools..."
/sbin/calicoctl-v1.4 get ippool -o yaml | tee ippool.yaml
if [ $? != 0 ]; then
    echo "Failed to get IPPools through calicoctl"
    exit 1
else if [ `cat ippool.yaml | wc -l` == 1 ]; then
    echo "No IPPools found to migrate."
    echo "Moving on..."
else
    /sbin/calicoctl-v1.5 apply -f ippool.yaml
    if [ $? != 0 ]; then
        echo "Failed to apply the IPPools"
        exit 1
    else
        echo "Migrated the IPPools!"
    fi
  fi
fi

# Get BGPPeers list with old calicoctl (from TPR) and save it as a yaml file.
# Apply the yaml file with the new calicoctl (to CRD)
echo; echo "Migrating BGPPeers..."
/sbin/calicoctl-v1.4 get bgppeers -o yaml | tee bgppeers.yaml
if [ $? != 0 ]; then
    echo "Failed to get Global BGP Peers through calicoctl"
    exit 1
else if [ `cat bgppeers.yaml | wc -l` == 1 ]; then
    echo "No BGPPeers found to migrate."
    echo "Moving on..."
else
    /sbin/calicoctl-v1.5 apply -f bgppeers.yaml
    if [ $? != 0 ]; then
        echo "Failed to apply the BGPPeers"
        exit 1
    else
        echo "Migrated the BGPPeers!"
    fi
  fi
fi

# List all the Felix configs using kubectl and save it in a yaml file.
# Change the apiVersion from 'projectcalico.org/v1' to 'crd.projectcalico.org/v1',
# rename resource kind from 'GlobalConfig' to 'GlobalFelixConfig' and save it in a new yaml file.
# Apply the modified yaml file.
echo; echo "Migrating GlobalFelixConfig..."
/sbin/kubectl get globalconfig --all-namespaces -o yaml | tee tpr-felixconfig.yaml
if [ $? != 0 ]; then
    echo "Failed to get Global Felix config through Kubectl"
    exit 1
else
    grep 'items\: \[\]' tpr-felixconfig.yaml 1>/dev/null
    if [ $? == 0 ]; then
        echo "No GlobalFelixConfig found to migrate."
        echo "Moving on..."
    else
        cat tpr-felixconfig.yaml | sed '/apiVersion/s/projectcalico\.org\/v1/crd\.projectcalico\.org\/v1/g' | sed '/kind/s/GlobalConfig/GlobalFelixConfig/g' |  sed -e '/^\s*creationTimestamp/d' -e '/^\s*uid/d' -e '/^\s*resourceVersion/d' -e '/^\s*namespace/d' -e '/^\s*selfLink/d' > crd-felixconfig.yaml
        echo; echo "Converted global-config.projectcalico.org/v1 to globalfelixconfigs.crd.projectcalico.org/v1"
        cat crd-felixconfig.yaml
        /sbin/kubectl apply -f crd-felixconfig.yaml
        if [ $? != 0 ]; then
            echo "Failed to apply the GlobalFelixConfig"
            exit 1
        else
            echo "Migrated the GlobalFelixConfig!"
        fi
    fi
fi


# List all the BGP configs using kubectl and save it in a yaml file.
# Change the apiVersion from 'projectcalico.org/v1' to 'crd.projectcalico.org/v1' and save it in a new yaml file.
# Apply the modified yaml file.
echo; echo "Migrating GlobalBGPConfig..."
/sbin/kubectl get globalbgpconfig --all-namespaces -o yaml | tee tpr-bgpconfig.yaml
if [ $? != 0 ]; then
    echo "Failed to get the Global BGP config through Kubectl"
    exit 1
else
    grep 'items\: \[\]' tpr-bgpconfig.yaml 1>/dev/null
    if [ $? == 0 ]; then
        echo "No GlobalBGPConfig found to migrate."
        /sbin/kubectl apply -f globalbgpconfig.yaml
        echo "Moving on..."
    else
        /sbin/kubectl apply -f globalbgpconfig.yaml
        cat tpr-bgpconfig.yaml | sed -e '/apiVersion/s/projectcalico\.org\/v1/crd\.projectcalico\.org\/v1/g'  -e '/kind/s/GlobalBgpConfig/GlobalBGPConfig/g' |  sed -e '/^\s*creationTimestamp/d' -e '/^\s*uid/d' -e '/^\s*resourceVersion/d' -e '/^\s*namespace/d' -e '/^\s*selfLink/d' > crd-bgpconfig.yaml
        echo; echo "Converted global-bgp-config.projectcalico.org/v1 to globalbgpconfigs.crd.projectcalico.org/v1"
        cat crd-bgpconfig.yaml
        /sbin/kubectl apply -f crd-bgpconfig.yaml
        if [ $? != 0 ]; then
            echo "Failed to apply the GlobalBGPConfig"
            /sbin/kubectl delete -f globalbgpconfig.yaml
            exit 1
        else
            echo "Migrated the GlobalBGPConfig!"
        fi
    fi
fi

echo; echo "Successfully migrated Calico data!"