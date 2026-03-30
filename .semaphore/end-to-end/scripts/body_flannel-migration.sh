#!/usr/bin/env bash
set -exo pipefail
echo "[INFO] starting job..."

export CNI_VERSION=${CNI_VERSION:-"v1.1.1"}
export DOCS_BASE=${DOCS_BASE:-"https://github.com/projectcalico/calico"}
export DOWNLEVEL_MANIFEST=${DOWNLEVEL_MANIFEST:-"https://github.com/projectcalico/calico/raw/release-${RELEASE_STREAM}/manifests/canal.yaml"}
export CALICO_MANIFEST=${CALICO_MANIFEST:-"manifests/flannel-migration/calico.yaml"}
export MIGRATION_MANIFEST=${MIGRATION_MANIFEST:-"manifests/flannel-migration/migration-job.yaml"}

if [ "${USE_HASH_RELEASE}" == "true" ]; then
 echo "[INFO] Using hash release for flannel migration"
  LATEST_HASHREL="https://latest-os.docs.eng.tigera.net/${RELEASE_STREAM}.txt"
  echo "Checking ${LATEST_HASHREL} for latest hash release url..."
  DOCS_URL=$(curl --retry 9 --retry-all-errors -sS ${LATEST_HASHREL})
  echo "Using $DOCS_URL for hash release base url"
else
  if [[ "${RELEASE_STREAM}" == "master" ]]; then
    echo "Cannot use latest release on master branch"
    exit 1
  else
    echo "[INFO] Using latest release for flannel migration"
    export DOCS_URL=$DOCS_BASE/raw/release-${RELEASE_STREAM}
  fi
fi

export BZ_LOCAL=${BZ_HOME}/.local
export KUBECONFIG=$BZ_LOCAL/kubeconfig
export PATH=$PATH:$BZ_LOCAL/bin

# Seems like modern OSes no longer include br_netfilter by default which breaks flannel. Install it in case we need it.
echo "[INFO] installing br_netfilter..."
sudo modprobe br_netfilter

mkdir -p "$BZ_LOGS_DIR"
cd "${BZ_HOME}"
bz provision |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/provision.log.gz")
cache store "$SEMAPHORE_JOB_ID" ../bz

# Install bridge CNI plugin (needed by kube-flannel manifest)
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cni-installer
  namespace: kube-system
  labels:
    app: cni-installer
spec:
  selector:
    matchLabels:
      app: cni-installer
  template:
    metadata:
      labels:
        app: cni-installer
    spec:
      nodeSelector:
        kubernetes.io/os: linux
      hostNetwork: true
      terminationGracePeriodSeconds: 0
      tolerations:
        - effect: NoSchedule
          operator: Exists
        - key: CriticalAddonsOnly
          operator: Exists
        - effect: NoExecute
          operator: Exists
      terminationGracePeriodSeconds: 0
      priorityClassName: system-node-critical
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      initContainers:
      - name: cni-installer
        image: quay.io/dosmith/cni-plugins:gen4
        command: ["/bin/bash", "-c", "cp -f /usr/src/plugins/bin/* /opt/cni/bin"]
        volumeMounts:
        - name: bindir
          mountPath: /opt/cni/bin
        securityContext:
          privileged: true
        resources:
          requests:
            cpu: 10m
            memory: 10Mi
      containers:
      - name: pause
        image: registry.k8s.io/pause
        resources:
          requests:
            cpu: 10m
            memory: 10Mi
      volumes:
      - name: bindir
        hostPath:
          path: /opt/cni/bin
EOF
# Update flannel.yaml to use the podCIDR that CRC sets up
wget -O flannel.yaml "$DOWNLEVEL_MANIFEST"
sed -i "s?10.244.0.0/16?192.168.0.0/16?g" ./flannel.yaml
kubectl apply -f - < ./flannel.yaml
sleep 30 # wait for flannel to come up
kubectl get po -A -owide
# Run a basic services test to check that flannel networking is working
K8S_E2E_FLAGS='--ginkgo.focus=should.serve.a.basic.endpoint.from.pods' ./bz.sh tests:run |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/e2e-tests-pre.log")
kubectl delete -n kube-system ds cni-installer || true  # remove the CNI installer daemonset
kubectl apply -f "$DOCS_URL/$CALICO_MANIFEST"
wget -O calico-migration.yaml "$DOCS_URL/$MIGRATION_MANIFEST"
kubectl apply -f - < ./calico-migration.yaml
sleep 5  # to make sure the job has started before we check its status
kubectl -n kube-system get jobs flannel-migration
kubectl -n kube-system describe jobs flannel-migration
kubectl get po -A -owide
kubectl wait --for=condition=complete --timeout=600s -n kube-system job/flannel-migration
kubectl -n kube-system get jobs flannel-migration
kubectl -n kube-system describe jobs flannel-migration
kubectl -n kube-system logs -l k8s-app=flannel-migration-controller
kubectl get po -A -owide
# delete the migration job because the presence of a non-Running pod in kube-system upsets the e2es.
kubectl -n kube-system delete job/flannel-migration || true
kubectl -n kube-system delete po -l k8s-app=flannel-migration-controller || true

# Run e2e on uplevel calico
./bz.sh tests:run |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/e2e-tests.log")
