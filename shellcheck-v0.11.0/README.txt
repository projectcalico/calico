This is a precompiled ShellCheck binary.
      https://www.shellcheck.net/

ShellCheck is a static analysis tool for shell scripts.
It's licensed under the GNU General Public License v3.0.
Information and source code is available on the website.

This binary was compiled on Mon Aug  4 00:22:40 UTC 2025.



      ====== Latest commits ======

commit aac0823e6b58f8a499e856e93738082691cbf212
Author: Vidar Holen <vidar@vidarholen.net>
Date:   Sun Aug 3 16:19:11 2025 -0700

    Stable version v0.11.0
    
    This release is dedicated to Satisfactory, even though my giant
    3D ball of rat's nest conveyor belt spaghetti is anything but.
    
      CHANGELOG
    
      ## v0.11.0 - 2025-08-03
      ### Added
      - SC2327/SC2328: Warn about capturing the output of redirected commands.
      - SC2329: Warn when (non-escaping) functions are never invoked.
      - SC2330: Warn about unsupported glob matches with [[ .. ]] in BusyBox.
      - SC2331: Suggest using standard -e instead of unary -a in tests.
      - SC2332: Warn about `[ ! -o opt ]` being unconditionally true in Bash.
      - SC3062: Warn about bashism `[ -o opt ]`.
      - Optional `avoid-negated-conditions`: suggest replacing `[ ! a -eq b ]`
        with `[ a -ne b ]`, and similar for -ge/-lt/=/!=/etc (SC2335).
      - Precompiled binaries for Linux riscv64 (linux.riscv64)
    
      ### Changed
      - SC2002 about Useless Use Of Cat is now disabled by default. It can be
        re-enabled with `--enable=useless-use-of-cat` or equivalent directive.
      - SC2236/SC2237 about replacing `[ ! -n .. ]` with `[ -z ]` and vice versa
        is now optional under `avoid-negated-conditions`.
      - SC2015 about `A && B || C` no longer triggers when B is a test command.
      - SC3012: Do not warn about `\<` and `\>` in test/[] as specified in POSIX.1-2024
      - Diff output now uses / as path separator on Windows
    
      ### Fixed
      - SC2218 about function use-before-define is now more accurate.
      - SC2317 about unreachable commands is now less spammy for nested ones.
      - SC2292, optional suggestion for [[ ]], now triggers for Busybox.
      - Updates for Bash 5.3, including `${| cmd; }` and `source -p`
    
      ### Removed
      - SC3013: removed since the operators `-ot/-nt/-ef` are specified in POSIX.1-2024
