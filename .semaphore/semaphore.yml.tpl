version: v1.0
name: Calico

execution_time_limit:
  hours: 4

agent:
  machine:
    type: e1-standard-2
    os_image: ubuntu1804

auto_cancel:
  running:
    when: "branch != 'master'"
  queued:
    when: "branch != 'master'"

promotions:
# Manual promotion for publishing a release.
- name: Publish official release
  pipeline_file: release/release.yml
# Cleanup after ourselves if we are stopped-short.
- name: Cleanup
  pipeline_file: cleanup.yml
  auto_promote:
    when: "result = 'stopped'"
# Have separate promotions for publishing images so we can re-run
# them individually if they fail, and so we can run them in parallel.
- name: Push apiserver images
  pipeline_file: push-images/apiserver.yml
  auto_promote:
    when: "branch =~ 'master|release-.*'"
- name: Push cni-plugin images
  pipeline_file: push-images/cni-plugin.yml
  auto_promote:
    when: "branch =~ 'master|release-'"
- name: Push kube-controllers images
  pipeline_file: push-images/kube-controllers.yml
  auto_promote:
    when: "branch =~ 'master|release-'"
- name: Push calicoctl images
  pipeline_file: push-images/calicoctl.yml
  auto_promote:
    when: "branch =~ 'master|release-'"
- name: Push typha images
  pipeline_file: push-images/typha.yml
  auto_promote:
    when: "branch =~ 'master|release-'"
- name: Push ALP images
  pipeline_file: push-images/alp.yml
  auto_promote:
    when: "branch =~ 'master|release-'"
- name: Push calico/node images
  pipeline_file: push-images/node.yml
  auto_promote:
    when: "branch =~ 'master|release-'"

global_job_config:
  secrets:
  - name: docker-hub
  prologue:
    commands:
    - checkout
    - export REPO_DIR="$(pwd)"
    - mkdir artifacts
    # Semaphore is doing shallow clone on a commit without tags.
    # unshallow it for GIT_VERSION:=$(shell git describe --tags --dirty --always)
    - git fetch --unshallow
    # Semaphore mounts a copy-on-write FS as /var/lib/docker in order to provide a pre-loaded cache of
    # some images. However, the cache is not useful to us and the copy-on-write FS is a big problem given
    # how much we churn docker containers during the build.  Disable it.
    - sudo systemctl stop docker
    - sudo umount /var/lib/docker && sudo killall qemu-nbd || true
    - sudo systemctl start docker
    # Free up space on the build machine.
    - sudo rm -rf ~/.kiex ~/.phpbrew ~/.rbenv ~/.nvm ~/.kerl ~/.sbt ~/.npm /usr/lib/jvm /opt/firefox* /opt/apache-maven* /opt/scala /usr/local/golang
    - echo $DOCKERHUB_PASSWORD | docker login --username "$DOCKERHUB_USERNAME" --password-stdin
    # Disable initramfs update to save space on the Semaphore VM (and we don't need it because we're not going to reboot).
    - sudo apt-get install -y -u crudini
    - sudo crudini --set /etc/initramfs-tools/update-initramfs.conf '' update_initramfs no
    - cat /etc/initramfs-tools/update-initramfs.conf
  epilogue:
    commands:
    - cd "$REPO_DIR"
    - .semaphore/publish-artifacts

blocks:

- name: "cni-plugin"
  run:
    when: "${FORCE_RUN} or change_in(['/*', '/cni-plugin/', '/libcalico-go/'], {exclude: ['/**/.gitignore', '/**/README.md', '/**/LICENSE']})"
  task:
    prologue:
      commands:
      - cd cni-plugin
    jobs:
    - name: "cni-plugin tests 1"
      commands:
      - ../.semaphore/run-and-monitor ci1.log make ci
    - name: "cni-plugin tests 2"
      commands:
      - ../.semaphore/run-and-monitor ci2.log make ci
    - name: "cni-plugin tests 3"
      commands:
      - ../.semaphore/run-and-monitor ci3.log make ci
    - name: "cni-plugin tests 4"
      commands:
      - ../.semaphore/run-and-monitor ci4.log make ci
    - name: "cni-plugin tests 5"
      commands:
      - ../.semaphore/run-and-monitor ci5.log make ci
    - name: "cni-plugin tests 6"
      commands:
      - ../.semaphore/run-and-monitor ci6.log make ci
    - name: "cni-plugin tests 7"
      commands:
      - ../.semaphore/run-and-monitor ci6.log make ci
