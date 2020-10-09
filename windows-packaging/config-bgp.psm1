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


# Function module to config BGP

# Return Null if no action is taken. Otherwise return action logs.
FUNCTION ProcessBgpRouter ($BgpId, $LocalAsn)
{
    # Look for existing BGP router with the correct ID.
    $found = $True
    try 
    {
        $router = Get-BgpRouter| Where-Object BgpIdentifier -eq $BgpId 
    }
    catch
    {
        $ErrorMessage = $_.Exception.Message
        Write-Output "Get-BgpRouter error:", $ErrorMessage

        $found = $False
    }
    if ($found)
    {
        if ($router.LocalASN -ne $localAsn) {
            # An existing BGP router with the wrong ASN; remove it.
            Remove-BgpRouter -Force
            Write-Output "Remove existing BGP router"
        }
        else
        {            
            # No action is taken. Nothing returned.
            return
        }
    } 

    # Add BGP router with the desired ID and AS number.
    Add-BgpRouter -BgpIdentifier $BgpId -LocalASN $localAsn  
    Write-Output "Add BGP router"
}

# Return Null if no action is taken. Otherwise return action logs.
FUNCTION ProcessBgpBlocks ($Blocks)
{
    $current_blocks = (Get-BgpCustomRoute).Network
    $unused_blocks = [System.Collections.ArrayList]$current_blocks

    foreach ($block in $Blocks)
    {
        if ($current_blocks -contains $block) 
        {
            $unused_blocks.Remove($block)
            continue
        }
        if ($block -ne "")
        {
            Add-BgpCustomRoute -Network $block
            Write-Output "Add custom route", $block
        }
    }

    # Remove unused blocks
    foreach ($unused_block in $unused_blocks)
    {
        Remove-BgpCustomRoute -Network $unused_block -Force

        Write-Output "Remove unused block ", $unused_block
    }
}

# Return Null if no action is taken. Otherwise return action logs.
FUNCTION ProcessBgpPeers ($Peerings, $LocalIp)
{
    $current_peers = Get-BgpPeer
    $unused_peers = [System.Collections.ArrayList]$current_peers
    $new_peers = New-Object System.Collections.ArrayList

    # Add peerings. We try to minimize calling to BGP daemon.
    foreach ($peering in $Peerings)
    {
        if (-not $peering.Name)
        {
            continue
        }

        $done = $False

        foreach ($current_peer in $current_peers)
        {
            if ($current_peer.PeerName -eq $peering.Name)
            {

                if (($current_peer.LocalIPAddress -eq $LocalIp) -And ($current_peer.PeerIPAddress -eq $peering.IP) -And ($current_peer.PeerASN -eq $peering.AS))
                {
                    # Peer exists and identical
                    # Do nothing
                } 
                else
                {
                    # Peer exists but differ
                    Remove-BgpPeer -Name $current_peer.PeerName -Force
                    # Defer the Add-BgpPeer call since it may conflict with another peering that we're about to
                    # delete.  For example if it is being renamed.
                    $new_peers.Add($peering)
                    Write-Output "Peering updated: ", $current_peer.PeerName
                }

                $done = $True

                # Remove this peer from unused.
                $unused_peers.Remove($current_peer)

                break
            }
        }

        if (-not $done)
        {
            Write-Output "New peering detected: ", $peering.Name
            # Defer the Add-BgpPeer call since it may conflict with another peering that we're about to
            # delete.  For example if it is being renamed.
            $new_peers.Add($peering)
        }
    }

    # Remove unused peerings first, in case a peering has been renamed.
    foreach ($unused_peer in $unused_peers)
    {
        Write-Output "Removing unused peer ", $unused_peer.PeerName
        Remove-BgpPeer -Name $unused_peer.PeerName -Force
    }

    foreach ($peering in $new_peers)
    {
        Write-Output "Adding peer ", $peering.Name
        Add-BgpPeer -Name $peering.Name -LocalIPAddress $LocalIp -PeerIPAddress $peering.IP -PeerASN $peering.AS
    }
}

Export-ModuleMember -Function ProcessBGPRouter
Export-ModuleMember -Function ProcessBGPBlocks
Export-ModuleMember -Function ProcessBGPPeers

