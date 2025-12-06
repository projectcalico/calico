: ${KUBECTL:=./bin/kubectl}

ns=azureserviceoperator-system
pod=$($KUBECTL get pod -A -o wide | grep "azureserviceoperator-controller-manager" | awk '{print $2}')
if [[ $pod == azureserviceoperator*  ]]; then
    echo "$pod -n $ns"
else
    echo "Can't find aso controller manager"
    exit 1
fi

${KUBECTL} logs $1 $pod -n $ns
