#!/bin/bash

# Copyright (c) 2022 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

my_dir=$(dirname $0)

excluded_dirs=(
  '.[a-z]*'
  'libbpf'
  'report'
)

excluded_files=(
  '*.log'
  'banned-regexps.txt'
  'banned-regexps-exceptions.txt'
  'DOC_STYLE_GUIDE.md'
)

declare -a grep_args
for pattern in "${excluded_dirs[@]}"; do
  grep_args[$i]="--exclude-dir=$pattern"
  ((i += 1))
done
for pattern in "${excluded_files[@]}"; do
  grep_args[$i]="--exclude=$pattern"
  ((i += 1))
done

problems="$(grep -r -I -i "${grep_args[@]}" -f "$my_dir/banned-regexps.txt" |
  grep -v -f "$my_dir/banned-regexps-exceptions.txt")"

if [ "$problems" ]; then
  echo "Some files matched the banned words list:"
  echo
  printf "%s" "$problems"
  echo
  echo
  exit 1
fi

