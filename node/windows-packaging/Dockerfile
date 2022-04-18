# Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

# This dockerfile is used to build the image used for running Calico for Windows
# as a daemonset using a HostProcess pod.
# This is inspired by and borrows from:
# https://github.com/kubernetes-sigs/sig-windows-tools/tree/master/hostprocess/calico

ARG WINDOWS_VERSION

# The files in this image are copied to $env:CONTAINER_SANDBOX_MOUNT_POINT on the host.
FROM mcr.microsoft.com/windows/nanoserver:${WINDOWS_VERSION}

ENV PATH="C:\Program Files\PowerShell;C:\utils;C:\Windows\system32;C:\Windows;"

COPY install-calico-windows.ps1 /
COPY calico-windows.zip /
COPY host-process-install.ps1 /

# The nanoserver image does not have powershell but this works because
# this container will be running on the host.
ENTRYPOINT ["powershell"]

