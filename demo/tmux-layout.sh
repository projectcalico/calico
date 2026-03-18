#!/bin/bash
# Launch tmux demo layout for KubeVirt Live Migration recording
#
# Layout:
#   +---------------------------+------------------------------------------------+
#   |  Pane 0: Commands         |  Pane 1: Live Watch                            |
#   |  (type/paste commands)    |  (VMIs, virt-launcher pods, active VMIM, WEP)  |
#   +---------------------------+------------------------------------------------+
#   |  Pane 2: vm2 shell / TCP stream (intra-cluster VM-to-VM connectivity)      |
#   +----------------------------------------------------------------------------+

SESSION=kubecon-demo

if [ -z "$BZ_ROOT_DIR" ]; then
    echo "ERROR: BZ_ROOT_DIR is not set. Export it before running this script."
    echo "  export BZ_ROOT_DIR=/path/to/your/gcp-kubevirt-cluster"
    exit 1
fi

# Kill existing session if any
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Resolve dynamic values from Taskvars.yml
TASKVARS="$BZ_ROOT_DIR/Taskvars.yml"
KUBECONFIG=$(grep '^KUBECONFIG:' "$TASKVARS" | awk '{print $2}')

export KUBECONFIG
VM1_IP=$(kubectl get vmi vm1 -o jsonpath='{.status.interfaces[0].ipAddress}' 2>/dev/null || echo '<VM1_IP>')

# Create session with large window
tmux new-session -d -s "$SESSION" -x 220 -y 55

# Split top/bottom (60/40)
tmux split-window -v -p 40 -t "$SESSION"

# Split top into left/right (50/50)
tmux select-pane -t 0
tmux split-window -h -p 50 -t "$SESSION"

# Make pane borders more visible for light terminal themes
tmux set-option -t "$SESSION" pane-border-style 'fg=black'
tmux set-option -t "$SESSION" pane-active-border-style 'fg=red'
tmux set-option -t "$SESSION" pane-border-status top
tmux set-option -t "$SESSION" pane-border-format ' #[fg=black,bold]#{pane_index} "#{pane_title}" '

# Optional: make status line cleaner for recording
tmux set-option -t "$SESSION" status-style 'bg=black,fg=white'
tmux set-option -t "$SESSION" message-style 'bg=black,fg=red'

# Set pane titles
tmux select-pane -t "$SESSION:0.0" -T "Commands"
tmux select-pane -t "$SESSION:0.1" -T "Live Watch"
tmux select-pane -t "$SESSION:0.2" -T "vm2 (TCP client)"

# Set env vars silently in all panes
for pane in 0 1 2; do
    tmux send-keys -t "$SESSION:0.$pane" \
      "export KUBECONFIG=$KUBECONFIG BZ_ROOT_DIR=$BZ_ROOT_DIR VM1_IP=$VM1_IP" Enter
    tmux send-keys -t "$SESSION:0.$pane" "clear" Enter
done

# Pane 1 (top-right): start the live watch
tmux send-keys -t "$SESSION:0.1" "watch -n 1 '
echo \"=== VirtualMachineInstances ===\" &&
kubectl get vmi -o custom-columns=NAME:.metadata.name,IP:.status.interfaces[0].ipAddress,NODE:.status.nodeName,PHASE:.status.phase 2>/dev/null &&
echo &&
echo \"=== Virt-Launcher Pods ===\" &&
kubectl get pods -l kubevirt.io=virt-launcher --field-selector=status.phase=Running -o custom-columns=NAME:.metadata.name,IP:.status.podIP,NODE:.spec.nodeName,STATUS:.status.phase 2>/dev/null &&
echo &&
echo \"=== VirtualMachineInstanceMigrations ===\" &&
VMIM_OUT=\$(kubectl get vmim -o custom-columns=NAME:.metadata.name,VMI:.spec.vmiName,PHASE:.status.phase --no-headers 2>/dev/null | awk '\''\$3 != \"Succeeded\" && \$3 != \"Failed\"'\'') &&
if [ -n \"\$VMIM_OUT\" ]; then
  echo \"NAME VMI PHASE\"
  echo \"\$VMIM_OUT\"
else
  echo \"No migration running\"
fi &&
echo &&
echo \"=== Calico WorkloadEndpoint (vm1 IP) ===\" &&
WEP_OUT=\$(calicoctl get workloadendpoint --allow-version-mismatch -o wide 2>/dev/null | grep \"$VM1_IP\") &&
if [ -n \"\$WEP_OUT\" ]; then
  echo \"\$WEP_OUT\"
else
  echo \"No WorkloadEndpoint found for IP $VM1_IP\"
fi
'" Enter

# Pane 2 (bottom): connect to vm2
tmux send-keys -t "$SESSION:0.2" "gkm connect vm2" Enter

# Pane 0 (top-left): ready with clean prompt
tmux select-pane -t "$SESSION:0.0"

# Attach
tmux attach -t "$SESSION"
