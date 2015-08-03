# -*- mode: ruby -*-
# vi: set ft=ruby :

# The version of calico to install
calico_docker_ver = "v0.5.3"

# Size of the cluster created by Vagrant
num_instances=2

# Change basename of the VM
instance_name_prefix="calico"

# The IP address of the first server
primary_ip = "172.17.8.101"

Vagrant.configure(2) do |config|
  # always use Vagrants insecure key
  config.ssh.insert_key = false

  # Use an official Ubuntu base box
  config.vm.box = "ubuntu/trusty64"

  # Set up each box
  (1..num_instances).each do |i|
    vm_name = "%s-%02d" % [instance_name_prefix, i]
    config.vm.define vm_name do |host|
      host.vm.hostname = vm_name

      ip = "172.17.8.#{i+100}"
      host.vm.network :private_network, ip: ip

      # Fix stdin: is not a tty error (http://foo-o-rama.com/vagrant--stdin-is-not-a-tty--fix.html)
      config.vm.provision "fix-no-tty", type: "shell" do |s|
        s.privileged = false
        s.inline = "sudo sed -i '/tty/!s/mesg n/tty -s \\&\\& mesg n/' /root/.profile"
      end

      # The docker provisioner installs docker.
      host.vm.provision :docker, images: [
          "busybox:latest",
          "calico/node:#{calico_docker_ver}",
          "quay.io/coreos/etcd:v2.0.11",
      ]

      # Replace docker with known good version.
      host.vm.provision :shell, inline: "stop docker", :privileged => true
      host.vm.provision :shell, inline: "wget -qO /usr/bin/docker https://github.com/Metaswitch/calico-docker/releases/download/#{calico_docker_ver}/docker", :privileged => true

      # Docker uses Consul for clustering. Install just on the first host.
      if i == 1
        # Download consul and start.
        host.vm.provision :shell, inline: <<-SHELL
          sudo apt-get install -y unzip
          curl -L --silent https://dl.bintray.com/mitchellh/consul/0.5.2_linux_amd64.zip -o consul.zip
          unzip consul.zip
          chmod +x consul
          nohup ./consul agent -server -bootstrap-expect 1 -data-dir /tmp/consul -client #{primary_ip} > consul.log &
        SHELL
      end

      # Set Docker to use consul for multihost.
      host.vm.provision :shell, inline: %Q|sudo sh -c 'echo "DOCKER_OPTS=\"--kv-store=consul:#{primary_ip}:8500\"" > /etc/default/docker'|

      # Restart docker.
      host.vm.provision :shell, inline: "sudo start docker"

      # download calicoctl.
      host.vm.provision :shell, inline: "wget -qO /usr/local/bin/calicoctl https://github.com/Metaswitch/calico-docker/releases/download/#{calico_docker_ver}/calicoctl", :privileged => true

      host.vm.provision :shell, inline: "chmod +x /usr/local/bin/calicoctl"

      # Ensure that the iptables kernel modules are loaded etc...
      host.vm.provision :shell, inline: "sudo calicoctl checksystem --fix"

      # Calico uses etcd for clustering. Install it on the first host only.
      if i == 1
        host.vm.provision :docker do |d|
          d.run "quay.io/coreos/etcd",
            args: "--net=host",
            cmd: "--advertise-client-urls http://#{primary_ip}:4001 "\
                 "--listen-client-urls http://0.0.0.0:4001 "
        end
      end

      # Ensure the vagrant and root users get the ETCD_AUTHORITY environment.
      host.vm.provision :shell, inline: %Q|echo 'export ETCD_AUTHORITY="#{primary_ip}:4001"' >> /home/vagrant/.profile|
      host.vm.provision :shell, inline: %Q|sudo sh -c 'echo "Defaults env_keep +=\"ETCD_AUTHORITY\"" >>/etc/sudoers'|
    end
  end
end
