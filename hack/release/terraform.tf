provider "google" {
  project = var.google_project
  region  = var.google_region
  zone    = var.google_zone
}

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
}

resource "google_compute_instance" "vm_instance" {
  name         = "${var.prefix}-calico-release-executor"
  machine_type = var.machine_type
  zone         = var.google_zone

  service_account {
    scopes = ["storage-ro", "cloud-platform", "compute-rw", "logging-write", "monitoring", "service-control", "service-management"]
  }

  tags = ["calico-release"]

  metadata = {
    ssh-keys = "ubuntu:${tls_private_key.ssh.public_key_openssh}"
  }

  connection {
    user        = "ubuntu"
    agent       = false
    private_key = tls_private_key.ssh.private_key_pem
    host        = self.network_interface.0.access_config.0.nat_ip
  }

  boot_disk {
    initialize_params {
      image = var.image
      type  = var.disk_type
      size  = var.disk_size
    }
  }

  network_interface {
    network = var.google_network

    access_config {
      // This empty field requests an Ephemeral IP
    }
  }
}

resource "null_resource" "configure_vm" {
  connection {
    user        = "ubuntu"
    agent       = false
    private_key = tls_private_key.ssh.private_key_pem
    host        = google_compute_instance.vm_instance.network_interface.0.access_config.0.nat_ip
  }

  // Install the necessary environment for release.
  provisioner "remote-exec" {
    inline = [
      "sudo apt update",
      "sudo apt install -y ca-certificates curl",
      "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg",
      "echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu bionic stable' | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null",
      "sudo apt update",
      "sudo apt install -y docker-ce docker-ce-cli containerd.io",
      "sudo apt install -y git make zip unzip",
      "sudo usermod -aG docker ubuntu"
    ]
  }

  // Authenticate the docker daemon with GCR, dockerhub, and quay.
  provisioner "file" {
    source      = var.gcr_auth_path
    destination = "/tmp/gcr-credentials.json"
  }
  provisioner "remote-exec" {
    inline = [
      "cat /tmp/gcr-credentials.json | docker login -u _json_key --password-stdin https://gcr.io",
      "cat /tmp/gcr-credentials.json | docker login -u _json_key --password-stdin https://eu.gcr.io",
      "cat /tmp/gcr-credentials.json | docker login -u _json_key --password-stdin https://asia.gcr.io",
      "cat /tmp/gcr-credentials.json | docker login -u _json_key --password-stdin https://us.gcr.io",
      "echo ${var.dockerhub_token} | docker login --username ${var.dockerhub_user} --password-stdin",
      "echo ${var.quay_token} | docker login --username ${var.quay_user} --password-stdin quay.io",
    ]
  }

  // Set GITHUB_TOKEN in the environment.
  provisioner "remote-exec" {
    inline = [
      "sudo sh -c 'echo GITHUB_TOKEN=${var.github_token} >> /etc/environment'",
    ]
  }

  // Clone the Calico repository. We do this via HTTPS to clone initially, but change the remote to SSH
  // to work around the fact that Terraform doesn't seem to forward SSH.
  provisioner "remote-exec" {
    inline = [
      "git clone https://github.com/projectcalico/calico /home/ubuntu/calico",
      "cd /home/ubuntu/calico",
      "git remote remove origin",
      "git remote add origin git@github.com:projectcalico/calico.git",
      "ssh-keyscan -H github.com >> ~/.ssh/known_hosts",
    ]
  }
}

resource "local_file" "local_ssh_key" {
  content  = tls_private_key.ssh.private_key_pem
  filename = "${path.root}/ssh_key"

  provisioner "local-exec" {
    command = "chmod 600 ${path.root}/ssh_key"
  }
}

resource "local_file" "local_ssh_key_pub" {
  content  = tls_private_key.ssh.public_key_openssh
  filename = "${path.root}/ssh_key.pub"

  provisioner "local-exec" {
    command = "chmod 644 ${path.root}/ssh_key.pub"
  }
}

output "instance_ip" {
  value = google_compute_instance.vm_instance.network_interface.0.access_config.0.nat_ip
}

output "instance_ssh_key" {
  value      = "${abspath(path.root)}/ssh_key"
  depends_on = [tls_private_key.ssh]
}

output "connect_command" {
  value      = "ssh -A -i ${abspath(path.root)}/ssh_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ubuntu@${google_compute_instance.vm_instance.network_interface.0.access_config.0.nat_ip}"
  depends_on = [tls_private_key.ssh]
}
