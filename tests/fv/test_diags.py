from sh import docker


def test_diags():
    docker_exec = docker.bake("exec")
    host1_exec = docker_exec.bake("-t", "host1", "bash", "-c")
    link = host1_exec("/code/dist/calicoctl diags")
    assert "https://transfer.sh/" in link
