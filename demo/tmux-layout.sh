#!/bin/bash
# Launch tmux demo layout for KubeVirt Live Migration recording
#
# Layout:
#   +---------------------------+---------------------------+
#   |  Pane 0: Commands         |  Pane 1: Watch            |
#   |  (type/paste commands)    |  (live VM & pod status)   |
#   +---------------------------+---------------------------+
#   |  Pane 2: TCP Stream from TOR node (external BGP)      |
#   +-------------------------------------------------------+

SESSION=kubecon-demo

if [ -z "$BZ_ROOT_DIR" ]; then
    echo "ERROR: BZ_ROOT_DIR is not set. Export it before running this script."
    echo "  export BZ_ROOT_DIR=/path/to/your/gcp-kubevirt-cluster"
    exit 1
fi

# Kill existing session if any
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create session with large window
tmux new-session -d -s "$SESSION" -x 220 -y 55

# Split top/bottom (60/40)
tmux split-window -v -p 40 -t "$SESSION"

# Split top into left/right (50/50)
tmux select-pane -t 0
tmux split-window -h -p 50 -t "$SESSION"

# Resolve dynamic values from Taskvars.yml
TASKVARS="$BZ_ROOT_DIR/Taskvars.yml"
KUBECONFIG=$(grep '^KUBECONFIG:' "$TASKVARS" | awk '{print $2}')
CLUSTER_NAME=$(grep '^CLUSTER_NAME:' "$TASKVARS" | awk '{print $2}')
GOOGLE_ZONE=$(grep '^GOOGLE_ZONE:' "$TASKVARS" | awk '{print $2}')
TOR_INSTANCE="${CLUSTER_NAME}nch-ubuntu1"

export KUBECONFIG
VM1_IP=$(kubectl get vmi vm1 -o jsonpath='{.status.interfaces[0].ipAddress}' 2>/dev/null || echo '<VM1_IP>')

# Set env vars in all panes
for pane in 0 1 2; do
    tmux send-keys -t "$SESSION:0.$pane" "export KUBECONFIG=$KUBECONFIG BZ_ROOT_DIR=$BZ_ROOT_DIR VM1_IP=$VM1_IP TOR_INSTANCE=$TOR_INSTANCE TOR_ZONE=$GOOGLE_ZONE" Enter
done

# Pane 1 (top-right): start the watch
tmux send-keys -t "$SESSION:0.1" "watch -n 1 'echo \"=== VirtualMachineInstances ===\" && kubectl get vmi -o custom-columns=NAME:.metadata.name,IP:.status.interfaces[0].ipAddress,NODE:.status.nodeName,PHASE:.status.phase 2>/dev/null && echo && echo \"=== Virt-Launcher Pods ===\" && kubectl get pods -l kubevirt.io=virt-launcher -o custom-columns=NAME:.metadata.name,IP:.status.podIP,NODE:.spec.nodeName,STATUS:.status.phase 2>/dev/null'" Enter

# Pane 2 (bottom): show TCP stream instructions
tmux send-keys -t "$SESSION:0.2" "echo \">> SSH: gcloud compute ssh ubuntu@\$TOR_INSTANCE --zone=\$TOR_ZONE  |  Then run: nc $VM1_IP 9999\"" Enter

# Pane 0 (top-left): mark ready
tmux select-pane -t "$SESSION:0.0"
tmux send-keys -t "$SESSION:0.0" "echo \"VM1_IP=\$VM1_IP  TOR_INSTANCE=\$TOR_INSTANCE  TOR_ZONE=\$TOR_ZONE  — Ready!\"" Enter

# Attach
tmux attach -t "$SESSION"
