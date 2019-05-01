---
title: calicoctl profile
canonical_url: 'https://docs.projectcalico.org/v1.6/reference/calicoctl/profile'
---

> NOTE: The `calicoctl profile` commands should NOT be used when running
> Calico with the Docker libnetwork driver.  The libnetwork driver manages
> the security policy for containers.

This sections describes the `calicoctl profile` commands.

Read the [calicoctl Overview](../calicoctl) for a
full list of calicoctl commands.

## Displaying the help text for 'calicoctl profile' commands

Run `calicoctl profile --help` to display the following help menu for the
calicoctl profile commands.

```

Usage:
  calicoctl profile show [--detailed]
  calicoctl profile add <PROFILE>
  calicoctl profile remove <PROFILE> [--no-check]
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> tag (add|remove) <TAG>
  calicoctl profile <PROFILE> rule add (inbound|outbound) [--at=<POSITION>]
    (allow|deny) [(
      (tcp|udp) [(from [(ports <SRCPORTS>)] [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
                [(to   [(ports <DSTPORTS>)] [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
           [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
           [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]  
      [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])]
    )]
  calicoctl profile <PROFILE> rule remove (inbound|outbound) (--at=<POSITION>|
    (allow|deny) [(
      (tcp|udp) [(from [(ports <SRCPORTS>)] [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
                [(to   [(ports <DSTPORTS>)] [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
           [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
           [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      icmpv6 [(type <ICMPTYPE> [(code <ICMPCODE>)])]
             [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
             [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
      [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])]
    )])
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile <PROFILE> rule update

Description:
  Modify available profiles and configure rules or tags.

Options:
  --detailed        Show additional information.
  --no-check        Remove a profile without checking if there are endpoints
                    associated with the profile.
  --at=<POSITION>   Specify the position in the chain where the rule should
                    be placed. Default: append at end.

Examples:
  Add and set up a rule to prevent all inbound traffic except pings from the 192.168/16 subnet
  $ calicoctl profile add only-local-pings
  $ calicoctl profile only-local-pings rule add inbound deny icmp
  $ calicoctl profile only-local-pings rule add inbound --at=0 allow from 192.168.0.0/16

```

## calicoctl profile commands


### calicoctl profile show
This command prints a list of the policy profiles known to Calico.

If the `--detailed` flag is passed into the command,
the command will print information about the endpoints
associated with each profile, including:
 - Profile name
 - Workload ID associated with profile
 - Endpoint ID associated with profile
 - Host owner of workload
 - Orchestrator running the workload
 - State of the workload


This command can be run on any Calico node.

Command syntax:

```
calicoctl profile show [--detailed]

    --detailed: Show information about workloads associated with profiles
```

Examples:

```
$ calicoctl profile show
+------------+
|    Name    |
+------------+
| PROF_A_C_E |
|   PROF_B   |
|   PROF_D   |
+------------+

$ calicoctl profile show --detailed
+------------+----------------+-----------------+------------------------------------------------------------------+----------------------------------+--------+
|    Name    |      Host      | Orchestrator ID |                           Workload ID                            |           Endpoint ID            | State  |
+------------+----------------+-----------------+------------------------------------------------------------------+----------------------------------+--------+
| PROF_A_C_E | calico-host-01 |      docker     | 15a483ab65cc60e2831859dd0eb3b3acde86cc464aea8f6bbbd35cb5395ed007 | ee033eba777f11e5abe9080027b2d0eb | active |
| PROF_A_C_E | calico-host-01 |      docker     | a549f09ed2c9ae2a840edc834dea0d14e686a4bf6195c791db283aed7f8b5e48 | 011af79a778011e5abe9080027b2d0eb | active |
| PROF_A_C_E | calico-host-02 |      docker     | ecbb19f9913236da5e03187fbfadf65a5761c49051adf54758d7f447852336fa | f6e1dd20777f11e5abe9080027b2d0eb | active |
|   PROF_B   | calico-host-01 |      docker     | fb028123092ed9a91f279f1aa11517cbd5b023ec4daf382cce8471b3fe41e9af | f2497552777f11e5abe9080027b2d0eb | active |
|   PROF_D   | calico-host-02 |      docker     | 6f103f1439c3d69ed014d4aa7f5b92dac7b892cbec627ac3b181ae4263e307de | faecf8be777f11e5abe9080027b2d0eb | active |
+------------+----------------+-----------------+------------------------------------------------------------------+----------------------------------+--------+

```

### calicoctl profile add \<PROFILE\>
This command allows you to create policy profiles to configure
networking policy for Calico endpoints.

When you create a new profile with this command, it includes default rules and
tags that make it act like a traditional security group: endpoints in the group
can communicate freely. However, you may modify the rules and tags to suit your
needs. See [AdvancedNetworkPolicy] for more discussion of profiles, rules
and tags.

This command can be run on any Calico node.

Command syntax:

```
calicoctl profile add <PROFILE>

    <PROFILE>: Name of policy profile to add.
```

Examples:

```
$ calicoctl profile add PROF_TEST
Created profile PROF_TEST
```

### calicoctl profile remove \<PROFILE\>
This command allows you to remove policy profiles from Calico.

If you try to remove a profile that is still associated with endpoints, the
command will fail and a warning message will be printed.  To remove the profile
anyway, you can run the command with the `--no-check` flag to remove the profile
without checking dependencies, or you can run the
[`calicoctl container`](./container) command that removes the profile
association from a container for each container associated with the profile.
Note that Felix remove the iptables security rules for a profile when a profile
is removed. All traffic to endpoints still associated with a deleted profile
will be dropped.

This command can be run on any Calico node.

Command syntax:

```
calicoctl profile remove <PROFILE> [--no-check]

    <PROFILE>: Name of profile to remove.

    --no-check: Remove a profile without checking if there are endpoints
                associated with the profile.
```

Examples:

```
$ calicoctl profile remove PROF_TEST
Deleted profile PROF_TEST
```

### calicoctl profile \<PROFILE\> tag show
This command shows the tags related to a given profile.

All endpoints with this policy profile have the tags applied. Tags are used in
rules to select which endpoints to allow or deny traffic to and from. See the
`calicoctl profile <PROFILE> rule add` command below for additional information.

This command can be run on any Calico node.

Command syntax:

```
calicoctl profile <PROFILE> tag show

    <PROFILE>: Name of profile whose tags will be printed.
```

Examples:

```
$ calicoctl profile PROF_TEST tag show
PROF_TEST
```

### calicoctl profile \<PROFILE\> tag (add|remove) \<TAG\>
This command allows you to add or remove a profile tag from the given profile.

An example use case for adding tags would be if you have multiple profiles
that serve a similar purpose, such as a group of web applications. You may have
backend service that talks to all of these web applications. This backend
service is using a profile called BACKEND.  It would be tedious to create
multiple rules on the BACKEND profile for each web application that the backend
service interacts with.  Instead, you can set a tag on the web application
profiles called WEB_APP, then create a rule on the BACKEND profile that allows
interaction from the WEB_APP tag.

This command can be run on any Calico node.

Command syntax:

```
calicoctl profile <PROFILE> tag (add|remove) <TAG>

    <PROFILE>: Name of profile to add or remove a tag from.
    <TAG>: Tag name to add or remove from profile.
```

Examples:

```
# Add the WEB_APP tag to the WEB_SERVER_A profile
$ calicoctl profile WEB_SERVER_A tag add WEB_APP
Tag WEB_APP added to profile WEB_SERVER_A

# View the tags of the WEB_SERVER_A profile
$ calicoctl profile PROF tag show
WEB_SERVER_A
WEB_APP

# Remove the WEB_APP tag from the WEB_SERVER_A profile
$ calicoctl profile WEB_SERVER_A tag remove WEB_APP
Tag WEB_APP removed from profile WEB_SERVER_A
```

### calicoctl profile \<PROFILE\> rule add (inbound|outbound) (allow|deny)
This command allows you to configure policy rules on your policy profiles.

You can configure rules to allow and/or deny specific traffic
to and from your containers, based on a variety of criteria.

You can filter traffic based on any combination of the following:
 - *Type* - udp, tcp, icmp/icmpv6 (including type and code)
 - *Source tag* - Profile tag, such as WEB_SERVER
 - *Source cidr* - such as 172.25.1.0/24
 - *Source port* - TCP/UDP only
 - *Destination tag* - Profile tag, such as DATA_SERVER
 - *Destination cidr* - such as 172.25.2.0/24
 - *Destination port* - TCP/UDP only

Rules are executed in order. If a packet matches the rule criteria, rule
evaluation stops and the allow/deny action is taken. If an endpoint is part of
multiple profiles, the packet is matched against the profiles in order. If it
does not match any rules, matching proceeds to the next profile. If the last
profile is evaluated without a match, the packet is denied.

#### Docker default networking
When a profile is created with `calicoctl profile add`, the base rules for the
profile are as follows:
```
Inbound rules:
   1 allow from tag <PROFILE>
Outbound rules:
   1 allow
```

The default inbound rules allow traffic from workloads associated
with the <PROFILE> and implicitly deny all other traffic to
the workloads.

The default outbound rules allow all traffic leaving the workloads.

This command allows you to add additional rules to your profiles
to filter traffic based on desired policy criteria.

This command can be run on any Calico node.

Command syntax:

```
calicoctl profile <PROFILE> rule add (inbound|outbound) [--at=<POSITION>]
  (allow|deny) [(
    (tcp|udp) [(from [(ports <SRCPORTS>)] [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
              [(to   [(ports <DSTPORTS>)] [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
    icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
         [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
         [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
    icmpv6 [(type <ICMPTYPE> [(code <ICMPCODE>)])]
           [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
           [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
    [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
    [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])]
  )]

    <POSITION>: Integer position in profile's rule list to insert this new rule.
    <PROFILE>: Name of profile to add rule to.
    <SRCPORTS>: Source port numbers to use in new rule (TCP/UDP only).
    <SRCTAG>: Source profile tag name to use in new rule.
    <SRCCIDR>: Source IP cidr to use in new rule.
    <DSTPORTS>: Destination port numbers to use in new rule (TCP/UDP only).
    <DSTTAG>: Destination profile tag name to use in new rule.
    <DSTCIDR>: Destination IP cidr to use in new rule.
    <ICMPTYPE>: ICMP type number .
    <ICMPCODE>: Specific code number related to ICMP type.
```

Note: Each IP address specified should match the IP version of each other IP
address and protocol in the rule.

Examples:

```
# Configure a WEB profile to allow ICMP pings, SSH, and HTTP traffic.
# WEB profile currently has default rules:
# Inbound rules:
#    1 allow from tag WEB
# Outbound rules:
#    1 allow

# Configure rule to allow inbound HTTP and SSH packets
$ calicoctl profile WEB rule add inbound allow tcp to ports 80,443

# Configure rule to allow inbound ICMP ping packets
$ calicoctl profile WEB rule add inbound allow icmp type 8

# Show the rules on the profile
$ calicoctl profile WEB rule show
Inbound rules:
   1 allow from tag WEB
   2 allow tcp to ports 80,443
   3 allow icmp type 8
Outbound rules:
   1 allow
```

### calicoctl profile \<PROFILE\> rule remove (inbound|outbound) (allow|deny)

This command allows you to remove existing policy rules from a
Calico policy profile. This command follows the same format as
the `calicoctl profile <PROFILE> rule add` command above.

Removing rules from a profile may be necessary to provide the
desired policy on your Calico nodes.  For example, you may have
multiple web applications using profile WEB where each web app
serves a different purpose.  You may want these web apps to
interact with each other, so you would want to remove the default
profile rule that allows traffic from workloads on same profile.
See the example code below to understand how to do this.

This command can be run on any Calico node.

Command syntax:

```
calicoctl profile <PROFILE> rule remove (inbound|outbound) (--at=<POSITION>|
  (allow|deny) [(
    (tcp|udp) [(from [(ports <SRCPORTS>)] [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
              [(to   [(ports <DSTPORTS>)] [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
    icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
         [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
         [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
    [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
    [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])]
  )])

    <POSITION>: Integer position in profile's rule list to insert this new rule.
    <PROFILE>: Name of profile to add rule to.
    <SRCPORTS>: Source port numbers to use in new rule (TCP/UDP only).
    <SRCTAG>: Source profile tag name to use in new rule.
    <SRCCIDR>: Source IP cidr to use in new rule.
    <DSTPORTS>: Destination port numbers to use in new rule (TCP/UDP only).
    <DSTTAG>: Destination profile tag name to use in new rule.
    <DSTCIDR>: Destination IP cidr to use in new rule.
    <ICMPTYPE>: ICMP type number .
    <ICMPCODE>: Specific code number related to ICMP type.
```

Examples:

```
# Consider profile WEB which has been configured to allow inbound
# ICMP pings, HTTP, and SSH traffic in addition to the default
# traffic rules:
# Inbound rules:
#    1 allow from tag WEB
#    2 allow tcp to ports 80,443
#    3 allow icmp type 8
# Outbound rules:
#    1 allow

# Remove the 1st rule that allows traffic from other workloads with
# the WEB tag.
$ calicoctl profile WEB rule remove inbound --at=1

# Show the rules on the profile
$ calicoctl profile WEB rule show
Inbound rules:
   1 allow tcp to ports 80,443
   2 allow icmp type 8
Outbound rules:
   1 allow

```

### calicoctl profile \<PROFILE\> rule show
This command prints the inbound and outbound rules that are configured on a
profile.

This command can be run on any Calico node.

Command syntax:

```
calicoctl profile <PROFILE> rule show

    <PROFILE>: Name of profile whose rules will be printed.
```

Examples:

```
# Default rules for newly created profile named PROF
$ calicoctl profile PROF rule show
Inbound rules:
   1 allow from tag PROF
Outbound rules:
   1 allow

```

### calicoctl profile \<PROFILE\> rule json
This command prints the inbound and outbound rules that are configured on a
profile in JSON format.

The output of this command can be saved to a file and used in the future to
quickly configure a profile (see the `calicoctl profile <PROFILE> rule update`
command below).

This command can be run on any Calico node.

Command syntax:

```
calicoctl profile <PROFILE> rule json

    <PROFILE>: Name of profile whose rules will be printed.
```

Examples:

```
# Default rules for newly created profile named PROF
$ calicoctl profile PROF rule json
{
  "inbound_rules": [
    {
      "action": "allow",
      "src_tag": "PROF"
    }
  ],
  "outbound_rules": [
    {
      "action": "allow"
    }
  ]
}
```

### calicoctl profile \<PROFILE\> rule update
This command allows you to import JSON data to quickly configure rules on a
profile.

The JSON data for this command must be passed into the command as stdin.

This command can be run on any Calico node.

Command syntax:

```
calicoctl profile <PROFILE> rule update

    <PROFILE>: Name of profile whose rules will be updated.
```

Examples:

```
# Configure a profile using JSON file web_rules.json with the following contents:
# {
#   "inbound_rules": [
#     {
#       "action": "allow",
#       "protocol": "tcp",
#       "dst_ports": [
#         80,
#         443
#       ]
#     },
#     {
#       "action": "allow",
#       "icmp_type": 8,
#       "protocol": "icmp"
#     }
#   ],
#   "outbound_rules": [
#     {
#       "action": "allow"
#     }
#   ]
# }

# Create profile
$ calicoctl profile add WEB
Created profile WEB

# Update profile rules using json file
$ calicoctl profile WEB rule update < web_rules.json
Successfully updated rules on profile WEB

# Show the rules on the profile
$ calicoctl profile WEB rule show
Inbound rules:
   1 allow tcp to ports 80,443
   2 allow icmp type 8
Outbound rules:
   1 allow
```
