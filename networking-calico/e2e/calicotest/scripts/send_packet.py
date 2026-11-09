# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
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

import sys

import scapy.all as scapy


def main(source_ip, destination_ip, id_string):
    """
    Sends a ping packet with a specified payload
    :param source_ip: The IP given as the source in the IP packet header
    :param destination_ip: The IP to address the IP packet to
    :param id_string: A string used to later identify whether this packet has
                      been received - included as the payload
    """
    packet = scapy.IP(src=source_ip, dst=destination_ip) / scapy.ICMP() / id_string
    scapy.send(packet)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Incorrect number of arguments supplied")
        sys.exit(1)
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
