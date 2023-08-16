<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/libbpf-logo-sideways-darkbg.png" width="40%">
  <img src="assets/libbpf-logo-sideways.png" width="40%">
</picture>

Libbpf sync
===========

Libbpf *authoritative source code* is developed as part of [bpf-next Linux source
tree](https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf-next) under
`tools/lib/bpf` subdirectory and is periodically synced to Github.

Most of the mundane mechanical things like bpf and bpf-next tree merge, Git
history transformation, cherry-picking relevant commits, re-generating
auto-generated headers, etc. are taken care by
[sync-kernel.sh script](https://github.com/libbpf/libbpf/blob/master/scripts/sync-kernel.sh).
But occasionally human needs to do few extra things to make everything work
nicely.

This document goes over the process of syncing libbpf sources from Linux repo
to this Github repository. Feel free to contribute fixes and additions if you
run into new problems not outlined here.

Setup expectations
------------------

Sync script has particular expectation of upstream Linux repo setup. It
expects that current HEAD of that repo points to bpf-next's master branch and
that there is a separate local branch pointing to bpf tree's master branch.
This is important, as the script will automatically merge their histories for
the purpose of libbpf sync.

Below, we assume that Linux repo is located at `~/linux`, it's current head is
at latest `bpf-next/master`, and libbpf's Github repo is located at
`~/libbpf`, checked out to latest commit on `master` branch. It doesn't matter
from where to run `sync-kernel.sh` script, but we'll be running it from inside
`~/libbpf`.

```
$ cd ~/linux && git remote -v | grep -E '^(bpf|bpf-next)'
bpf     https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git (fetch)
bpf     ssh://git@gitolite.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git
(push)
bpf-next
https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git (fetch)
bpf-next
ssh://git@gitolite.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git (push)
$ git branch -vv | grep -E '^? (master|bpf-master)'
* bpf-master                               2d311f480b52 [bpf/master] riscv, bpf: Fix patch_text implicit declaration
  master                                   c8ee37bde402 [bpf-next/master] libbpf: Fix bpf_xdp_query() in old kernels
$ git checkout bpf-master && git pull && git checkout master && git pull
...
$ git log --oneline -n1
c8ee37bde402 (HEAD -> master, bpf-next/master) libbpf: Fix bpf_xdp_query() in old kernels
$ cd ~/libbpf && git checkout master && git pull
Your branch is up to date with 'libbpf/master'.
Already up to date.
```

Running setup script
--------------------

First step is to always run `sync-kernel.sh` script. It expects three arguments:

```
$ scripts/sync-kernel.sh <libbpf-repo> <kernel-repo> <bpf-branch>
```

Note, that we'll store script's entire output in `/tmp/libbpf-sync.txt` and
put it into PR summary later on. **Please store scripts output and include it
in PR summary for others to check for anything unexpected and suspicious.**

```
$ scripts/sync-kernel.sh ~/libbpf ~/linux bpf-master | tee /tmp/libbpf-sync.txt
Dumping existing libbpf commit signatures...
WORKDIR:          /home/andriin/libbpf
LINUX REPO:       /home/andriin/linux
LIBBPF REPO:      /home/andriin/libbpf
...
```

Most of the time this will go very uneventful. One expected case when sync
script might require user intervention is if `bpf` tree has some libbpf fixes,
which is nowadays not a very frequent occurence. But if that happens, script
will show you a diff between expected state as of latest bpf-next and synced
Github repo state. And will ask if these changes look good. Please use your
best judgement to verify that differences are indeed from expected `bpf` tree
fixes. E.g., it might look like below:

```
Comparing list of files...
Comparing file contents...
--- /home/andriin/linux/include/uapi/linux/netdev.h     2023-02-27 16:54:42.270583372 -0800
+++ /home/andriin/libbpf/include/uapi/linux/netdev.h    2023-02-27 16:54:34.615530796 -0800
@@ -19,7 +19,7 @@
  * @NETDEV_XDP_ACT_XSK_ZEROCOPY: This feature informs if netdev supports AF_XDP
  *   in zero copy mode.
  * @NETDEV_XDP_ACT_HW_OFFLOAD: This feature informs if netdev supports XDP hw
- *   oflloading.
+ *   offloading.
  * @NETDEV_XDP_ACT_RX_SG: This feature informs if netdev implements non-linear
  *   XDP buffer support in the driver napi callback.
  * @NETDEV_XDP_ACT_NDO_XMIT_SG: This feature informs if netdev implements
/home/andriin/linux/include/uapi/linux/netdev.h and /home/andriin/libbpf/include/uapi/linux/netdev.h are different!
Unfortunately, there are some inconsistencies, please double check.
Does everything look good? [y/N]:
```

If it looks sensible and expected, type `y` and script will proceed.

If sync is successful, your `~/linux` repo will be left in original state on
the original HEAD commit. `~/libbpf` repo will now be on a new branch, named
`libbpf-sync-<timestamp>` (e.g., `libbpf-sync-2023-02-28T00-53-40.072Z`).

Push this branch into your fork of `libbpf/libbpf` Github repo and create a PR:

```
$ git push --set-upstream origin libbpf-sync-2023-02-28T00-53-40.072Z
Enumerating objects: 130, done.
Counting objects: 100% (115/115), done.
Delta compression using up to 80 threads
Compressing objects: 100% (28/28), done.
Writing objects: 100% (32/32), 5.57 KiB | 1.86 MiB/s, done.
Total 32 (delta 21), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (21/21), completed with 9 local objects.
remote:
remote: Create a pull request for 'libbpf-sync-2023-02-28T00-53-40.072Z' on GitHub by visiting:
remote:      https://github.com/anakryiko/libbpf/pull/new/libbpf-sync-2023-02-28T00-53-40.072Z
remote:
To github.com:anakryiko/libbpf.git
 * [new branch]                libbpf-sync-2023-02-28T00-53-40.072Z -> libbpf-sync-2023-02-28T00-53-40.072Z
Branch 'libbpf-sync-2023-02-28T00-53-40.072Z' set up to track remote branch 'libbpf-sync-2023-02-28T00-53-40.072Z' from 'origin'.
```

**Please, adjust PR name to have a properly looking timestamp. Libbpf
maintainers will be very thankful for that!**

By default Github will turn above branch name into PR with subject "Libbpf sync
2023 02 28 t00 53 40.072 z". Please fix this into a proper timestamp, e.g.:
"Libbpf sync 2023-02-28T00:53:40.072Z". Thank you!

**Please don't forget to paste contents of /tmp/libbpf-sync.txt into PR
summary!**

Once PR is created, libbpf CI will run a bunch of tests to check that
everything is good. In simple cases that would be all you'd need to do. In more
complicated cases some extra adjustments might be necessary.

**Please, keep naming and style consistent.** Prefix CI-related fixes with `ci: `
prefix. If you had to modify sync script, prefix it with `sync: `. Also make
sure that each such commit has `Signed-off-by: Your Full Name <your@email.com>`,
just like you'd do that for Linux upstream patch. Libbpf closely follows kernel
conventions and styling, so please help maintaining that.

Including new sources
---------------------

If entirely new source files (typically `*.c`) were added to the library in the
kernel repository, it may be necessary to add these to the build system
manually (you may notice linker errors otherwise), because the script cannot
handle such changes automatically. To that end, edit `src/Makefile` as
necessary. Commit
[c2495832ced4](https://github.com/libbpf/libbpf/commit/c2495832ced4239bcd376b9954db38a6addd89ca)
is an example of how to go about doing that.

Similarly, if new public API header files were added, the `Makefile` will need
to be adjusted as well.

Updating allow/deny lists
-------------------------

Libbpf CI intentionally runs a subset of latest BPF selftests on old kernel
(4.9 and 5.5, currently). It happens from time to time that some tests that
previously were successfully running on old kernels now don't, typically due to
reliance on some freshly added kernel feature. It might look something like this in [CI logs](https://github.com/libbpf/libbpf/actions/runs/4206303272/jobs/7299609578#step:4:2733):

```
  All error logs:
  serial_test_xdp_info:FAIL:get_xdp_none errno=2
  #283     xdp_info:FAIL
  Summary: 49/166 PASSED, 5 SKIPPED, 1 FAILED
```

In such case we can either work with upstream to fix test to be compatible with
old kernels, or we'll have to add a test into a denylist (or remove it from
allowlist, like was [done](https://github.com/libbpf/libbpf/commit/ea284299025bf85b85b4923191de6463cd43ccd6)
for the case above).

```
$ find . -name '*LIST*'
./ci/vmtest/configs/ALLOWLIST-4.9.0
./ci/vmtest/configs/DENYLIST-5.5.0
./ci/vmtest/configs/DENYLIST-latest.s390x
./ci/vmtest/configs/DENYLIST-latest
./ci/vmtest/configs/ALLOWLIST-5.5.0
```

Please determine which tests need to be added/removed from which list. And then
add that as a separate commit. **Please keep using the same branch name, so
that the same PR can be updated.** There is no need to open new PRs for each
such fix.

Regenerating vmlinux.h header
-----------------------------

To compile latest BPF selftests against old kernels, we check in pre-generated
[vmlinux.h](https://github.com/libbpf/libbpf/blob/master/.github/actions/build-selftests/vmlinux.h)
header file, located at `.github/actions/build-selftests/vmlinux.h`, which
contains type definitions from latest upstream kernel. When after libbpf sync
upstream BPF selftests require new kernel types, we'd need to regenerate
`vmlinux.h` and check it in as well.

This will looks something like this in [CI logs](https://github.com/libbpf/libbpf/actions/runs/4198939244/jobs/7283214243#step:4:1903):

```
  In file included from progs/test_spin_lock_fail.c:5:
  /home/runner/work/libbpf/libbpf/.kernel/tools/testing/selftests/bpf/bpf_experimental.h:73:53: error: declaration of 'struct bpf_rb_root' will not be visible outside of this function [-Werror,-Wvisibility]
  extern struct bpf_rb_node *bpf_rbtree_remove(struct bpf_rb_root *root,
                                                      ^
  /home/runner/work/libbpf/libbpf/.kernel/tools/testing/selftests/bpf/bpf_experimental.h:81:35: error: declaration of 'struct bpf_rb_root' will not be visible outside of this function [-Werror,-Wvisibility]
  extern void bpf_rbtree_add(struct bpf_rb_root *root, struct bpf_rb_node *node,
                                    ^
  /home/runner/work/libbpf/libbpf/.kernel/tools/testing/selftests/bpf/bpf_experimental.h:90:52: error: declaration of 'struct bpf_rb_root' will not be visible outside of this function [-Werror,-Wvisibility]
  extern struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root) __ksym;
                                                     ^
  3 errors generated.
  make: *** [Makefile:572: /home/runner/work/libbpf/libbpf/.kernel/tools/testing/selftests/bpf/test_spin_lock_fail.bpf.o] Error 1
  make: *** Waiting for unfinished jobs....
  Error: Process completed with exit code 2.
```

You'll need to build latest upstream kernel from `bpf-next` tree, using BPF
selftest configs. Concat arch-agnostic and arch-specific configs, build kernel,
then use bpftool to dump `vmlinux.h`:

```
$ cd ~/linux
$ cat tools/testing/selftests/bpf/config \
   tools/testing/selftests/bpf/config.x86_64 > .config
$ make -j$(nproc) olddefconfig all
...
$ bpftool btf dump file ~/linux/vmlinux format c > ~/libbpf/.github/actions/build-selftests/vmlinux.h
$ cd ~/libbpf && git add . && git commit -s
```

Check in generated `vmlinux.h`, don't forget to use `ci: ` commit prefix, add
it on top of sync commits. Push to Github and let libbpf CI do the checking for
you. See [this commit](https://github.com/libbpf/libbpf/commit/34212c94a64df8eeb1dd5d064630a65e1dfd4c20)
for reference.

Troubleshooting
---------------

If something goes wrong and sync script exits early or is terminated early by
user, you might end up with `~/linux` repo on temporary sync-related branch.
Don't worry, though, sync script never destroys repo state, it follows
"copy-on-write" philosophy and creates new branches where necessary. So it's
very easy to restore previous state. So if anything goes wrong, it's easy to
start fresh:

```
$ git branch | grep -E 'libbpf-.*Z'
  libbpf-baseline-2023-02-28T00-43-35.146Z
  libbpf-bpf-baseline-2023-02-28T00-43-35.146Z
  libbpf-bpf-tip-2023-02-28T00-43-35.146Z
  libbpf-squash-base-2023-02-28T00-43-35.146Z
* libbpf-squash-tip-2023-02-28T00-43-35.146Z
$ git cherry-pick --abort
$ git checkout master && git branch | grep -E 'libbpf-.*Z' | xargs git br -D
Switched to branch 'master'
Your branch is up to date with 'bpf-next/master'.
Deleted branch libbpf-baseline-2023-02-28T00-43-35.146Z (was 951bce29c898).
Deleted branch libbpf-bpf-baseline-2023-02-28T00-43-35.146Z (was 3a70e0d4c9d7).
Deleted branch libbpf-bpf-tip-2023-02-28T00-43-35.146Z (was 2d311f480b52).
Deleted branch libbpf-squash-base-2023-02-28T00-43-35.146Z (was 957f109ef883).
Deleted branch libbpf-squash-tip-2023-02-28T00-43-35.146Z (was be66130d2339).
Deleted branch libbpf-tip-2023-02-28T00-43-35.146Z (was 2d311f480b52).
```

You might need to do the same for your `~/libbpf` repo sometimes, depending at
which stage sync script was terminated.
