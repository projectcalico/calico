#!/bin/bash
# Copyright (c) 2020 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script attempts to clean up the container file system to remove as many
# packages, binaries and libraries as possible.  It scans a keep-list of binaries
# to find what libraries they reference; removes all but a keep-list of packages
# and then removes any left-over binaries and libraries.

set -e

# Sanity check: the file is created by the Dockerfile.
if [ ! -f /in-the-container ]; then
  echo "You really don't want to run this outside the container!"
  exit 1
fi

# List of directories to scan for binaries so that we can find out what libraries they link to.
bin_dirs=(
  # /bin is symlinked on UBI so only need the /usr version.
  /sbin
  /usr/bin
  /usr/sbin
  /usr/local/bin
)

# List of grep regex patterns to cover the binaries that we want to keep in the image.  We'll
# scan these binaries to find the libraries they link to below.
bin_allow_list_patterns=(
  # Our binaries.
  calico
  bird
  versions

  # Init daemon.
  runit
  runsv
  sv
  utmpset

  # Felix dependencies.
  '/arp$'       # Used to add arp entries
  '/conntrack$' # Used to remove conntrack entries.
  '/ip$' # iproute2; used to add/manipulate routes etc.
  bpftool

  # iptables/ip sets
  xtables
  iptables
  ip6tables
  ipset

  # kmod is a multi-binary backing depmod/insmod/etc; used by iptables
  kmod depmod insmod modinfo modprobe rmmod lsmod

  # Shell and basic shell tools; needed for runit.
  '\['
  alias
  basename
  coreutils
  '/bash$'
  '/sh$'
  '/cat$'
  '/cd$'
  '/cp$'
  '/ln$'
  '/date$'
  '/ls$'
  echo
  '/env$'
  false
  true
  getopt
  '/hostname$'
  '/gzip$'
  '/grep$'
  '/nice$'
  join
  '/kill$'
  mkdir
  mknod
  more
  less
  printf
  '/read$'
  readlink
  '/rm$'
  '/sed$'
  sleep
  sort
  '/stat$'
  tail
  '/tc$'
  touch
  '/tee$'
  timeout
  '/test$'
  ulimit
  uniq
  wait
  which
  whoami
  yes
  zcat
  zless
  zmore

  # Needed by cgroup v2
  nsenter

  # Used by this script.
  '/find$'
  '/ldd$'
  '/ldconfig$'
)

# Convert the binary allow list into arguments for grep.
declare -a grep_args
i=0
for pattern in "${bin_allow_list_patterns[@]}"; do
  grep_args[$i]="-e"
  grep_args[((i + 1))]=${pattern}
  ((i += 2))
done

# Use an associative array as a set, we collect the paths of the binaries that we want
# to keep as keys in the array.
echo "Finding binaries that we want to keep:"
declare -A binaries_to_keep
while read -r path; do
  echo "KEEP: $path"
  binaries_to_keep[$path]=true
done < <(find "${bin_dirs[@]}" \( -type f -or -type l \) | grep "${grep_args[@]}")


# find-libs analyses a binary and prints a list of the names of the library .so files that
# it uses (excluding path).
find-libs() {
  b=$1
  # We'll use the keys of this map as a set in order to dedupe the filenames.
  local -A libs
  ldd=$(ldd "$b" 2>/dev/null || true)
  # Avoid parsing ldd errors as lists of libs.
  if [[ "$ldd" =~ not\ a\ dynamic|statically\ linked ]]; then
    return
  fi
  # ldd output looks like this:
  # 	linux-vdso.so.1 (0x00007f873e1d3000)
  #		libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f873e161000)
  # Ignore the "=>" and the parenthesized address; slurp up the other names.
  # I'm not sure if the RHS of the => can ever have a different name so we add them
  # both to the set.
  for part in $ldd; do
    if [[ "$part" =~ \( ]]; then
      continue
    fi
    if [[ "$part" == "=>" ]]; then
      continue
    fi
    libs["$(basename "${part}")"]=true
  done
  # Dump the keys of the map that we use as a set.
  echo "${!libs[@]}"
}

# Use an associative array as a set, building up the set of in-use libraries.
# Note: "${!binaries_to_keep[@]}" expands to the keys of the associative array.
echo "Finding in-use libraries:"
declare -A libs
for b in "${!binaries_to_keep[@]}"; do
  printf "%s -> " "$b"
  for lib in $(find-libs "$b"); do
    printf "%s " "${lib}"
    libs[${lib}]=true
  done
  printf "\n"
done
echo

# Libraries are usually symlinked.  Expand the set of allowed libraries to include
# the targets of symlinks (or we'd keep the symlink and delete the actual library!).
echo "Analysing library symlinks..."
while read -r path; do
  file=$(basename "${path}")
  target_path=$(readlink "$path" || true)
  if [[ -z "$target_path" ]] || [[ "$target_path" = "${path}" ]]; then
    continue
  fi
  target_file=$(basename "${target_path}")
  if [[ -n "${libs[${file}]}" ]] && [[ -z "${libs[${target_file}]}" ]]; then
    echo "${file} -> ${target_file}"
    libs[${target_file}]=true
  fi
done < <(find /usr/lib64 \( -type l \))
echo

# We only capture the filenames of the libraries above, search for the paths.
echo "Resolving in-use libraries to paths..."
declare -A libs_to_keep
while read -r path; do
  file=$(basename "${path}")
  if [[ -n "${libs[${file}]}" ]]; then
    echo "IN USE: $path"
    libs_to_keep[$path]=true
    continue
  fi
  # Well-known plugins, not directly linked.
  if [[ "$path" =~ xtables|netfilter|conntrack|ct_|pam|libnss|libresolv ]] && ! [[ "$path" =~ systemd ]] ; then
    echo "PLUGIN: $path"
    libs_to_keep[$path]=true
    continue
  fi
done < <(find /usr/lib64 \( -type f -or -type l \))

# Now remove all but a keep-list of RPM packages.  Cleaning up packages with rpm itself updates the
# metadata that CVE scanners look for so it's best to do this before we clean up any remaining
# binaries and libraries that we don't want.
packages_to_keep=(
  bash
  ca-certificates
  conntrack-tools
  coreutils-single
  crypto-policies
  filesystem
  findutils
  glibc
  grep
  gzip
  iproute
  ipset
  iptables
  kmod
  langpacks
  libacl
  libattr
  libcap
  libcrypto
  libelf
  libgcc
  libibverbs
  libmnl
  libnetfilter
  libnfnetlink
  libnftnl
  libnl3
  libnss
  libpcap
  libpwquality
  libselinux
  libzstd
  ncurses
  net-tools
  openssl-libs
  p11-kit-trust
  pam
  pcre
  redhat-release
  rootfiles
  rpm
  sed
  setup
  shadow-utils
  shared-mime-info
  systemd-libs
  tzdata
  util-linux
  which
  xz-libs
  zlib
)

# Convert the keep list into arguments for grep.
declare -a grep_args
i=0
for pattern in "${packages_to_keep[@]}"; do
  grep_args[$i]="-e"
  grep_args[((i + 1))]=${pattern}
  ((i += 2))
done

# List all the packages and use an inverse grep to filter out the ones that we want to
# keep.  The output from microdnf repoquery includes the full version of each package
# but rpm only wants the package name, not its version.
#
# Example:
#  "audit-libs-3.0-0.17.20191104git1c2f876.el8.x86_64" -> "audit-libs"
#
# Use sed to extract everything up to the version.  The regex matches dash-separated
# words at the start of the line, where a word must begin with an alphabetic character.
# This allows things like "krb5" but disallows "1.2.3"
packages_to_remove=$(microdnf repoquery --installed |
  sed -e 's/^\(\([a-zA-Z][a-zA-Z0-9_+]*\)\(-\([a-zA-Z][a-zA-Z0-9_+]*\)\)*\).*/\1/g' |
  grep -v "${grep_args[@]}")


echo "Removing ${packages_to_remove}"
# Removing one of the packages deletes rc.local, move it out of the way.
mv /etc/rc.local /etc/rc.local.bak
rpm -e --nodeps $packages_to_remove
mv /etc/rc.local.bak /etc/rc.local

# Sanity check that we didn't remove anything we want to keep.
for path in "${!binaries_to_keep[@]}"; do
  if [[ -e "$path" ]]; then
    continue
  fi
  echo "Binary is missing after RPM cleanup: $path"
  exit 1
done
for path in "${!libs_to_keep[@]}"; do
  if [[ -e "$path" ]]; then
    continue
  fi
  echo "Library is missing after RPM cleanup: $path"
  exit 1
done

# Then delete any binaries and libraries that we don't want to keep.
while read -r path; do
  if [[ -n "${binaries_to_keep[$path]}" ]]; then
    continue
  fi
  echo "DEL: $path"
  rm -f "$path"
done < <(find "${bin_dirs[@]}" \( -type f -or -type l \))

while read -r path; do
  if [[ -n "${libs_to_keep[$path]}" ]]; then
    continue
  fi
  echo "DEL: $path"
  rm -f "$path"
done < <(find /usr/lib64 \( -type f -or -type l \))

# We deleted a lot of libraries, update the cache.
rm /etc/ld.so.cache
ldconfig

# Delete some easy pickings: caches, X, RPMs, this script!
rm -rf \
  /var/cache/* \
  /tmp/rpms \
  '@System.solv' \
  /etc/X11 \
  /usr/share/gcc-8 \
  /usr/share/X11 \
  /usr/share/zsh \
  /in-the-container \
  /usr/bin/ldd \
  "$0"
