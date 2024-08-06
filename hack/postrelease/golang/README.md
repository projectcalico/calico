# Open-source postrelease tests!

## How to run

You can use ginkgo to run the tests:

```
$ ginkgo run tests/oss
```

To run specific tests, find the label for the tests you want to run and
then pass that label to ginkgo:

```
$ ginkgo labels tests/oss
oss: ["asset", "calico", "docker", "flannel", "github", "helm", "image_name", "openstack"]

# ginkgo run --label-filter helm tests/oss
```

## Structure

```
/
  pkg/      # All the various utility functions
  tests/    # The actual test suites
    oss/    # Test suites for Calico OSS
```

In future, more test suites will be added to `tests`; for example, maybe `tests/operator` for
operator-related validations. 

