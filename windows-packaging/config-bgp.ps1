# Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
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

Write-Host "Start to reconfigure BGP"

# Read in template-generated config.
. .\peerings.ps1
. .\blocks.ps1

ipmo .\config-bgp.psm1

ProcessBgpRouter -BgpId $bgp_id -LocalAsn $local_asn

ProcessBgpBlocks -Blocks $blocks

ProcessBgpPeers -Peerings $peerings -LocalIp $local_ip

Write-Host "Reconfigure BGP completed"
