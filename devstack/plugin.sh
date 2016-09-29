
# Devstack plugin code for Calico
# ===============================

function install_configure_etcd {

    # Install etcd from package sources (=> our PPA).
    install_package etcd

    # Stop the etcd service:
    sudo service etcd stop || true

    # Delete any existing etcd database:
    sudo rm -rf /var/lib/etcd/*

    # Mount a RAM disk at /var/lib/etcd:
    sudo mount -t tmpfs -o size=512m tmpfs /var/lib/etcd

    # Add the following to the bottom of /etc/fstab so that the RAM
    # disk gets reinstated at boot time:
    # tmpfs /var/lib/etcd tmpfs nodev,nosuid,noexec,nodiratime,size=512M 0 0

    IP=`hostname -I | awk '{print $1}'`

    # Edit /etc/init/etcd.conf: Find the line which begins exec
    # /usr/bin/etcd and edit it, substituting for <controller_fqdn>
    # and <controller_ip> appropriately.
    if $CALICO_COMPUTE_ONLY; then
	# Configure an etcd proxy.
	sudo sed -i "s/exec.*/exec \/usr\/bin\/etcd --proxy on \
  --initial-cluster \"$SERVICE_HOST=http:\/\/$SERVICE_HOST:2380\"/" /etc/init/etcd.conf
    else
	# Configure an etcd master node.
	sudo sed -i "s/exec.*/exec \/usr\/bin\/etcd --name=\"$HOSTNAME\" \
  --advertise-client-urls=\"http:\/\/$IP:2379,http:\/\/$IP:4001\" \
  --listen-client-urls=\"http:\/\/0.0.0.0:2379,http:\/\/0.0.0.0:4001\" \
  --listen-peer-urls \"http:\/\/0.0.0.0:2380\" \
  --initial-advertise-peer-urls \"http:\/\/$IP:2380\" \
  --initial-cluster-token \"$TOKEN\" \
  --initial-cluster \"$HOSTNAME=http:\/\/$IP:2380\" \
  --initial-cluster-state \"new\"/" /etc/init/etcd.conf
    fi

    # Start the etcd service:
    sudo service etcd start
}

mode=$1				# stack, unstack or clean
phase=$2			# pre-install, install, post-config or extra

if is_service_enabled calico; then
    case $mode in

	stack)
	    # Called by stack.sh four times for different phases of
	    # its run.
	    echo Calico plugin: stack

	    case $phase in

		pre-install)
		    # Called after system (OS) setup is complete and
		    # before project source is installed.
		    echo Calico plugin: pre-install

		    # Add Calico PPA as a package source.
		    sudo apt-add-repository -y ppa:project-calico/kilo-testing
		    REPOS_UPDATED=False

		    # Also add BIRD project PPA as a package source.
		    LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 sudo add-apt-repository -y ppa:cz.nic-labs/bird

		    ;;

		install)
		    # Called after the layer 1 and 2 projects source
		    # and their dependencies have been installed.
		    echo Calico plugin: install

		    # Upgrade dnsmasq.
		    install_package dnsmasq-base dnsmasq-utils

		    # Install ipset.
		    install_package ipset

		    # Install BIRD.
		    install_package bird

		    # Install and configure etcd.
		    install_configure_etcd

		    # Install posix-spawn.
		    pip_install git+https://github.com/projectcalico/python-posix-spawn.git@1f74fbedb569d4e45f11e9e32d3dca74623f432c#egg=posix-spawn

		    # Install the Calico agent (Felix).
		    FELIX_DIR=${DEST}/felix
		    git_clone ${FELIX_REPO:-https://github.com/projectcalico/felix.git} $FELIX_DIR ${FELIX_BRANCH:-master}
		    cd $FELIX_DIR
		    pip_install .

		    # Install networking-calico.
		    pushd ../networking-calico
		    pip_install .
		    popd

		    # Also install python-etcd from the Calico project's GitHub.
		    pip_install -I git+git://github.com/projectcalico/python-etcd.git

		    ;;

		post-config)
		    # Called after the layer 1 and 2 services have
		    # been configured. All configuration files for
		    # enabled services should exist at this point.
		    echo Calico plugin: post-config


		    # Update qemu configuration (shouldn't be anything
		    # in there so safe to blow away)
		    sudo sh -c "cat > /etc/libvirt/qemu.conf" << EOF
user = "root"
group = "root"
cgroup_device_acl = [
    "/dev/null", "/dev/full", "/dev/zero",
    "/dev/random", "/dev/urandom",
    "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
    "/dev/rtc", "/dev/hpet", "/dev/net/tun",
]
EOF

		    # Use the Calico plugin.  We make this change here, instead
		    # of putting 'Q_PLUGIN=calico' in the settings file,
		    # because the latter would require adding Calico plugin
		    # support to the core DevStack repository.
		    iniset $NEUTRON_CONF DEFAULT core_plugin calico

		    # Reset service_plugins to be empty, as the Calico plugin
		    # itself supports the 'router' extension.
		    inidelete $NEUTRON_CONF DEFAULT service_plugins

		    # Propagate ENABLE_DEBUG_LOG_LEVEL to neutron.conf, so that
		    # it applies to the Calico DHCP agent on each compute node.
		    iniset $NEUTRON_CONF DEFAULT debug $ENABLE_DEBUG_LOG_LEVEL
		    ;;

		extra)
		    # Called near the end after layer 1 and 2 services
		    # have been started.
		    echo Calico plugin: extra

		    # Run Felix and tail its log file.
		    run_process calico-felix "sudo /usr/local/bin/calico-felix"
		    tail_log calico-log "/var/log/calico/felix.log"

		    # Run script to automatically generate and
		    # maintain BIRD config for the cluster.
		    run_process calico-bird "HOST_IP=$HOST_IP /opt/stack/networking-calico/devstack/auto-bird-conf.sh"

		    # Run the Calico DHCP agent.
		    sudo mkdir /var/log/neutron || true
		    sudo chown `whoami` /var/log/neutron
		    run_process calico-dhcp "/usr/local/bin/calico-dhcp-agent --config-file $NEUTRON_CONF"

		    ;;

		*)
		    echo Calico plugin: unexpected phase $phase
		    ;;

	    esac
	    ;;

	unstack)
	    # Called by unstack.sh before other services are shut
	    # down.
	    echo Calico plugin: unstack
	    ;;

	clean)
	    # Called by clean.sh before other services are cleaned,
	    # but after unstack.sh has been called.
	    echo Calico plugin: clean
	    ;;

	*)
	    echo Calico plugin: unexpected mode $mode
	    ;;

    esac
fi
