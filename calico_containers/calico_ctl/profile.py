"""
calicoctl profile --help
Configure profile members and networking

Usage:
  calicoctl profile show [--detailed]
  calicoctl profile (add|remove) <PROFILE>
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> tag (add|remove) <TAG>
  calicoctl profile <PROFILE> rule add (inbound|outbound) [--at=<POSITION>] (allow|deny) <RULE...>
  calicoctl profile <PROFILE> rule remove (inbound|outbound) (--at=<POSITION>|<RULE>)
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile <PROFILE> rule update

Rule:
  A rule must be of one of the following formats:
 
  TCP/IP RULE:
   (tcp|udp) [from [ports <SRCPORTS>] [tag <SRCTAG>] [<SRCCIDR>]]
      [to   [ports <DSTPORTS>] [tag <DSTTAG>] [<DSTCIDR>]]

  ICMP RULE:
    icmp [type <ICMPTYPE> [code <ICMPCODE>]]
         [from [tag <SRCTAG>] [<SRCCIDR>]]
         [to   [tag <DSTTAG>] [<DSTCIDR>]]

  GLOBAL:
    [from [tag <SRCTAG>] [<SRCCIDR>]] 
    [to   [tag <DSTTAG>] [<DSTCIDR>]]

Examples:
  Add and set up a rule to prevent all inbound traffic except pings from the 192.168/16 subnet
  $ calicoctl profile add only-local-pings
  $ calicoctl profile only-local-pings rule add inbound deny icmp
  $ calicoctl profile only-local-pings rule add inbound --at=0 allow from 192.168.0.0/16
"""