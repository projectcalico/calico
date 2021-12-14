# Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
ARG WINDOWS_VERSION
FROM --platform=linux/amd64 alpine:latest as base

# We can't RUN commands in the Windows image build.
# Create dirs we need that we copy over in the final stage.
RUN mkdir /CalicoUpgrade /CalicoBin

ADD build/* /CalicoBin/

FROM mcr.microsoft.com/windows/nanoserver:${WINDOWS_VERSION}

COPY --from=base /CalicoUpgrade /CalicoUpgrade
COPY --from=base /CalicoBin /CalicoBin

# nanoserver defaults to ContainerUser however we need admin to run icacls
USER ContainerAdministrator

ENTRYPOINT cmd.exe \
	/C \
	copy /y c:\CalicoBin\calico-windows-upgrade.zip c:\CalicoUpgrade & \
	tar -x -f c:\CalicoUpgrade\calico-windows-upgrade.zip -C c:\CalicoUpgrade & \
	del c:\CalicoUpgrade\calico-windows-upgrade.zip & \
	dir c:\CalicoUpgrade & \
	icacls.exe c:\CalicoUpgrade & \
	icacls.exe c:\CalicoUpgrade /inheritance:r & \
	icacls.exe c:\CalicoUpgrade /grant:r SYSTEM:(OI)(CI)(F) & \
	icacls.exe c:\CalicoUpgrade /grant:r BUILTIN\Administrators:(OI)(CI)(F) & \
	icacls.exe c:\CalicoUpgrade /grant:r BUILTIN\Users:(OI)(CI)(RX) & \
	icacls.exe c:\CalicoUpgrade & \
	ping -t localhost > NUL
