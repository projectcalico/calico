# Calico Testing Guide

## Standardized Test Parameters

All Makefiles in this repository that support ginkgo-based tests (ut, fv, st targets) now accept the following standardized environment variables:

### Environment Variables

- **GINKGO_FOCUS** - Focus string to filter tests by regex pattern (default: `.*`)
  - Example: `GINKGO_FOCUS="TestName"`
  
- **GINKGO_SKIP** - Skip string to exclude tests by regex pattern (default: empty)
  - Example: `GINKGO_SKIP="SlowTest"`
  
- **GINKGO_ARGS** - Additional ginkgo arguments (default: empty)
  - Example: `GINKGO_ARGS="-ginkgo.v -ginkgo.dryRun"`
  
- **WHAT** - Package paths to test (default: `.`)
  - Example: `WHAT="./pkg/mypackage"`

### Usage Examples

#### Run specific test by name
```bash
make -C libcalico-go ut GINKGO_FOCUS="EventWatch"
```

#### Skip certain tests
```bash
make -C felix fv GINKGO_SKIP="SlowTest|FlakyTest"
```

#### Run with verbose output
```bash
make -C calicoctl ut GINKGO_ARGS="-ginkgo.v"
```

#### Run tests in specific package
```bash
make -C typha ut WHAT="./pkg/syncproto"
```

#### Combine multiple parameters
```bash
make -C felix fv GINKGO_FOCUS="My Test" GINKGO_SKIP="Slow" GINKGO_ARGS="-ginkgo.v"
```

### Component-Specific Notes

#### Felix
Felix has different levels of support across its test targets:
- **fv** target: Supports all parameters (GINKGO_FOCUS, GINKGO_SKIP, GINKGO_ARGS, WHAT via run-batches script)
- **ut** target: Only supports GINKGO_ARGS (passed to run-coverage script)
- **ut-no-cover, ut-watch** targets: Support all parameters

Felix also has additional FV test batching support:
```bash
make -C felix fv FV_NUM_BATCHES=5 FV_BATCHES_TO_RUN="1 2" GINKGO_FOCUS="BPF"
make -C felix ut-no-cover GINKGO_FOCUS="Wireguard" GINKGO_SKIP="Slow"
```

#### CNI Plugin
The CNI plugin tests run against different datastores:
```bash
make -C cni-plugin ut DATASTORE_TYPE=etcdv3 GINKGO_FOCUS="IPAM"
```

#### Calicoctl
The calicoctl tests use `WHAT` with a default of `*` to match the original behavior:
```bash
# Test a specific subdirectory (use directory name, not path with ./)
make -C calicoctl ut WHAT="commands"
```

### Affected Makefiles

The following Makefiles have been updated to support these standardized parameters:

- `libcalico-go/Makefile` (ut, fv targets)
- `felix/Makefile` (fv, ut-no-cover, ut-watch targets; ut only supports GINKGO_ARGS)
- `calicoctl/Makefile` (ut target)
- `typha/Makefile` (ut, ut-no-cover, ut-watch targets)
- `api/Makefile` (ut target)
- `cni-plugin/Makefile` (ut target)
- `app-policy/Makefile` (ut target)

### Legacy Support

All existing invocations without these parameters will continue to work with default values.
