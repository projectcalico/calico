# `lib/std/log` — Calico standard logging package

## Goals

1. Provide a single Calico-standard logging package. All Calico code logs
   through `github.com/projectcalico/calico/lib/std/log`.
2. Hide the concrete logger behind an interface. Today's implementation is
   logrus; tomorrow it could be slog, zap, or anything else, and no caller
   needs to change.
3. Consolidate the duplicated configuration code spread across
   `felix/logutils`, `typha/pkg/logutils`, and `libcalico-go/lib/logutils`
   into one place.
4. Make the per-component prefix ("felix", "typha", "calico/node", …) a
   property of *how you obtain a logger*, not a side effect of a global
   `ConfigureFormatter` call that happens somewhere at startup.

## Non-goals

- Re-deriving the output format. The current Calico formatter
  (`YYYY-MM-DD HH:MM:SS.mmm [LEVEL][PID] component/file.go line: message k=v`)
  is preserved byte-for-byte. Operators grep against this format.
- Replacing the logrus implementation in this change. logrus stays, just
  hidden.
- Solving structured logging (JSON, OTel) or context-carrying loggers
  (`logger.WithContext(ctx)`). The interface is designed not to preclude
  these, but they are not in scope here.

## Package shape

### Public surface

```go
package log

// Logger is what callers depend on. It mirrors the verbs the codebase
// already uses, so migration is mostly mechanical.
type Logger interface {
    Trace(args ...any); Tracef(format string, args ...any)
    Debug(args ...any); Debugf(format string, args ...any)
    Info(args ...any);  Infof(format string, args ...any)
    Warn(args ...any);  Warnf(format string, args ...any)
    Error(args ...any); Errorf(format string, args ...any)
    Fatal(args ...any); Fatalf(format string, args ...any)
    Panic(args ...any); Panicf(format string, args ...any)

    WithField(key string, value any) Logger
    WithFields(fields Fields) Logger
    WithError(err error) Logger

    Level() Level
    IsLevelEnabled(level Level) bool
}

type Fields map[string]any

type Level int
const (
    PanicLevel Level = iota
    FatalLevel
    ErrorLevel
    WarnLevel
    InfoLevel
    DebugLevel
    TraceLevel
)

// New returns a Logger labelled with the given component name.
// The component appears in every log line as part of the file prefix
// (e.g. "felix/calc_graph.go").
func New(component string) Logger

// Top-level functions back a default Logger (no component prefix).
// They make `import log "github.com/projectcalico/calico/lib/std/log"`
// behave like `import log "github.com/sirupsen/logrus"` for the call sites
// that don't need a per-component logger.
func Info(args ...any)
func Infof(format string, args ...any)
func WithField(key string, value any) Logger
func WithFields(fields Fields) Logger
func WithError(err error) Logger
// ... full set ...

// SetLevel sets the global level. Callable any time. Useful for early-startup
// adjustments before Configure has run.
func SetLevel(level Level)

// SetComponent sets the global component prefix. Callable any time.
// Configure may override this.
func SetComponent(name string)

// Configure performs full destination setup. Must be called exactly once
// per process, at startup. Panics if called twice. Idempotent only in the
// trivial sense that re-importing the package does not re-Configure.
func Configure(opts Options) error

type Options struct {
    // Component is the prefix used in log lines. Equivalent to a prior
    // SetComponent call.
    Component string

    // Screen, File, Syslog control destinations. A nil entry disables
    // that destination.
    Screen *ScreenConfig
    File   *FileConfig
    Syslog *SyslogConfig

    // DebugFilenameRegex, when non-nil, restricts debug-level logs to
    // source files whose basename matches the regex. The escape valve
    // felix uses to drill into one subsystem without firehosing everywhere.
    DebugFilenameRegex *regexp.Regexp

    // DebugDisableLogDropping forces all logs to be queued even if the
    // background destination's channel is full. Off by default; turn on
    // in tests and bug-hunting.
    DebugDisableLogDropping bool

    // SingleThreaded skips the standard logger's internal mutex.
    // Safe when all writes go through the background hook (typha pattern).
    SingleThreaded bool

    // Metrics. Optional; nil counters are silently ignored.
    Counters Counters
}

type ScreenConfig struct { Level Level }
type FileConfig   struct { Level Level; Path string }
type SyslogConfig struct { Level Level; Tag  string }

type Counters struct {
    DroppedLogs prometheus.Counter
    WriteErrors prometheus.Counter
}
```

### What lives in the package

Beyond the core `Logger` + `Configure`:

- **`RateLimitedLogger`** — ported from
  `libcalico-go/lib/logutils/ratelimitedlogger.go`. Returns the same
  `Logger` interface from its builder methods, so callers can store a
  rate-limited logger in a `Logger`-typed field.
- **`Summarizer`** — ported from `felix/logutils/summary.go`. It is
  logging-shaped (its job is to periodically emit one log line summarising
  a loop's operations) so it lives with the logger.
- **`IsSensitiveParam` / `RedactURL`** — ported from
  `libcalico-go/lib/logutils/sensitive.go`. These are used almost
  exclusively when logging config values, so they ride along.
- **Testing helpers** — `RedirectTo(testing.TB)` replaces
  `ConfigureLoggingForTestingTB` and `RedirectLogrusToTestingTB`.

### What does *not* live in the package

- **Profiling signal handlers** (`DumpHeapMemoryProfile`,
  `DumpCPUProfile`, `RegisterProfilingSignalHandlers`) move to a new
  `lib/std/profile` package. They are not logging.
- **logrus types**. No `logrus.Entry`, `logrus.Fields`, `logrus.Level`,
  `logrus.Hook`, `*logrus.Logger` is exposed in any signature. Code that
  needs raw logrus must import logrus directly — which is precisely what
  this refactor exists to discourage.

### Internal layout

Files inside the package (none of these are exported types):

```
lib/std/log/
  DESIGN.md           # this file
  logger.go           # Logger interface, Fields, Level constants
  default.go          # package-level functions + default Logger
  configure.go        # Options + Configure() + SetLevel/SetComponent
  formatter.go        # Calico formatter (internal, used by impl)
  destination.go      # Destination, BackgroundHook, file/syslog/stream destinations (all internal)
  ratelimited.go      # RateLimitedLogger
  summarizer.go       # Summarizer
  redact.go           # IsSensitiveParam, RedactURL
  testing.go          # RedirectTo(testing.TB)
  impl_logrus.go      # logrus-backed implementation of Logger
```

The split is "interface and surface" vs "implementation"; the latter
imports logrus, the former does not.

### `lib/std/profile`

```
lib/std/profile/
  profile.go          # DumpHeap, DumpCPU, RegisterSignalHandlers(opts)
  signals_linux.go    # SIGUSR1/SIGUSR2 wiring
  signals_other.go    # no-op stubs for non-Linux
```

`RegisterSignalHandlers` takes an explicit options struct
(`{HeapPath, CPUPath string}`) so the package has no dependency on felix's
`config.Config`. Callers map their config to those fields.

## Early-startup logging

The existing `ConfigureEarlyLogging` / `ConfigureLogging` split exists so
that components can log during config loading (between "process started"
and "config resolved"). With Configure called only once, the replacement
flow is:

1. Package `init()` sets up a default screen-only logger at `InfoLevel`
   with no component prefix. Logs work immediately on import.
2. Early in `main()` a component may call `SetComponent("felix")` and
   `SetLevel(level)` based on env vars to mirror today's
   `ConfigureEarlyLogging`.
3. Once config has loaded, the component calls `Configure(Options{...})`
   to install destinations.

`SetLevel` and `SetComponent` remain valid after `Configure` (level is
the common one — felix already adjusts the global level when config
changes).

## Migration plan

This work is too large for one PR. The proposed sequence:

1. **PR 1: Create the packages.** Land `lib/std/log` and `lib/std/profile`
   with full functionality and tests. Do not touch any callers. Do not
   delete the existing `logutils` packages.
2. **PR 2: Migrate felix.** Replace all felix imports of
   `felix/logutils`, `libcalico-go/lib/logutils`, and direct
   `github.com/sirupsen/logrus` with `lib/std/log`. Delete
   `felix/logutils`. Felix is the first migration target because it is
   the largest single consumer and shakes out the interface against the
   most-used patterns. Profiling code moves to `lib/std/profile` in this
   PR too (felix is its only caller).
3. **PR 3+: Migrate the remaining components.** Typha, libcalico-go,
   node, goldmane, kube-controllers, calicoctl, cni-plugin, apiserver,
   confd, app-policy, key-cert-provisioner, release, guardian,
   whisker-backend, pod2daemon, etc. One per PR.
4. **Final PR: Delete the old `logutils` packages.**
   `libcalico-go/lib/logutils` and `typha/pkg/logutils` go away when
   nothing imports them.

Each migration PR is the same mechanical change:

```diff
-import (
-    log "github.com/sirupsen/logrus"
-    "github.com/projectcalico/calico/libcalico-go/lib/logutils"
-)
+import (
+    "github.com/projectcalico/calico/lib/std/log"
+)

-var logger = log.WithField("component", "calc")
+var logger = log.New("calc")

-rl := logutils.NewRateLimitedLogger(logutils.OptInterval(10*time.Second))
+rl := log.NewRateLimitedLogger(log.WithInterval(10*time.Second))

-felixlogutils.ConfigureEarlyLogging()
-...
-felixlogutils.ConfigureLogging(configParams)
+log.SetComponent("felix")
+log.SetLevel(earlyLevel)
+...
+log.Configure(log.Options{
+    Component: "felix",
+    Screen:    &log.ScreenConfig{Level: ...},
+    File:      &log.FileConfig{Level: ..., Path: configParams.LogFilePath},
+    Syslog:    &log.SyslogConfig{Level: ..., Tag: "calico-felix"},
+    DebugFilenameRegex:      configParams.LogDebugFilenameRegex,
+    DebugDisableLogDropping: configParams.DebugDisableLogDropping,
+    Counters: log.Counters{
+        DroppedLogs: counterFelixLogsDropped,
+        WriteErrors: counterFelixLogErrors,
+    },
+})
```

A handful of call sites use logrus features the interface does not
expose (hooks, raw `*logrus.Logger`, `StandardLogger().SetNoLock()`).
Each will be handled when its migration PR is opened — most resolve to
an Options flag (`SingleThreaded` for `SetNoLock`), and the few that
genuinely need raw logrus (the apiserver klog adapter, the release tool's
rotating file hook) are documented as exceptions in their PR.

## Open questions

- **Hooks.** logrus exposes a `Hook` interface that some code uses
  (apiserver klog adapter, release tool's rotatefilehook). Do we expose
  our own `Hook` interface on `lib/std/log` for these cases, or do we
  fold their use cases into `Configure` options? Provisional answer:
  fold the rotating-file case into `FileConfig` (native rotation), and
  treat the klog adapter as a one-off solved during apiserver
  migration. Revisit if more hook use cases appear.
- **Context-carrying loggers.** Several call sites would benefit from
  `logger.WithContext(ctx)` and pulling trace/span IDs out automatically.
  Out of scope here; the interface leaves room to add it later.
- **JSON output.** Not in scope. If we want structured output for log
  aggregators, the interface is the right place to add `Configure`
  options (`Options.Format`) without breaking callers.
