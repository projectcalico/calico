version: v1.0
name: Calico

execution_time_limit:
  hours: 4

agent:
  machine:
    type: e1-standard-2
    os_image: ubuntu2004

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
- name: Publish openstack packages
  pipeline_file: push-images/packaging.yaml
  auto_promote:
    when: "branch =~ 'master'"

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
    - sudo rm -rf ~/{.kerl,.kiex,.npm,.nvm,.phpbrew,.rbenv,.sbt} /opt/{apache-maven*,firefox*,scala} /usr/lib/jvm /usr/local/{aws2,golang,phantomjs*}
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

- name: "Prerequisites"
  dependencies: []
  task:
    jobs:
    - name: "Pre-flight checks"
      commands:
      - make ci-preflight-checks

- name: "Felix: BPF UT/FV tests on new kernel"
  run:
    when: "${FORCE_RUN} or change_in(['/*', '/api/', '/libcalico-go/', '/typha/', '/felix/'], {exclude: ['/**/.gitignore', '/**/README.md', '/**/LICENSE']})"
  dependencies: ["Prerequisites"]
  task:
    prologue:
      commands:
      - cd felix
      - export GOOGLE_APPLICATION_CREDENTIALS=$HOME/secrets/secret.google-service-account-key.json
      - export SHORT_WORKFLOW_ID=$(echo ${SEMAPHORE_WORKFLOW_ID} | sha256sum | cut -c -8)
      - export ZONE=europe-west3-c
      - export VM_PREFIX=sem-${SEMAPHORE_PROJECT_NAME}-${SHORT_WORKFLOW_ID}-
      - echo VM_PREFIX=${VM_PREFIX}
      - export REPO_NAME=$(basename $(pwd))
      - export NUM_FV_BATCHES=8
      - mkdir artifacts
      - ./.semaphore/create-test-vms ${VM_PREFIX}
    jobs:
    - name: UT/FV tests on new kernel
      execution_time_limit:
        minutes: 180
      commands:
      - ./.semaphore/run-tests-on-vms ${VM_PREFIX}
    epilogue:
      always:
        commands:
        - ./.semaphore/collect-artifacts-from-vms ${VM_PREFIX}
        - ./.semaphore/publish-artifacts
        - ./.semaphore/clean-up-vms ${VM_PREFIX}
    secrets:
    - name: google-service-account-for-gce

after_pipeline:
  task:
    jobs:
    - name: Reports
      commands:
        - test-results gen-pipeline-report --force
