# Advanced Network Policy

Calico endpoints are assigned their network policy by configuring them with a policy profile.  In the previous examples we created profiles and assigned endpoints to them.  By default, `calicoctl profile add` adds default config to profiles so endpoints with the profile can all communicate with one another.  In this section, we look at how to customize policy profiles for more advanced policy.

## Overview

A policy profile comprises two elements: *tags* and *rules*.  

*Tags* identify different groups or sets of Calico endpoints.  A tag might represent a role or network permission, for example, you might define a tag `db_access` that represents permission to send data to your database containers on port 3590.

*Rules* are the policy statements that Calico's firewall will enforce for your endpoints.

## Worked Example

This example assumes you have a working Calico-enabled cluster, as described in [Getting Started](./GettingStarted.md)

Let's create a new profile and look at the default rules.

    ./calicoctl profile add WEB
    ./calicoctl profile WEB rule show

You should see the following output.

    Inbound rules:
       1 allow from tag WEB 
    Outbound rules:
       1 allow

Notice that profiles define policy for inbound packets and outbound packets separately.  This profile allows inbound traffic from other endpoints with the tag `WEB`, and (implicitly) denies inbound traffic from all other addresses.  It allows all outbound traffic regardless of destination.

Let's modify this profile to make it more appropriate for a public webserver. First, let's remove the default rule that allows traffic between nodes in the same profile:
```
./calicoctl profile WEB rule remove inbound --at=1
```

Then, let's allow TCP traffic on ports 80 and 443 and also allow ICMP ping traffic (which is type 8).

```
./calicoctl profile WEB rule add inbound allow tcp to ports 80,443
./calicoctl profile WEB rule add inbound allow icmp type 8
```
(By default, the add command appends to the list, but it also supports the `--at` parameter to trigger an insert.)

Now, we can list the rules again and see the changes:

```
./calicoctl profile WEB rule show
```

should print

```
Inbound rules:
   1 allow tcp to ports 80,443
   2 allow icmp type 8
Outbound rules:
   1 allow
```

calicoctl also supports importing rules in JSON format.  Let's say your WEB containers will need access to some backend services.  Create a profile called APP for these services.

    ./calicoctl profile add APP

For this example, let's say the APP containers present a service on port 7890.  We'll define a new tag, `APP_7890` to give containers access to this service port.  Using a tag allows us to grant and revoke access to different other profiles.  In this example, the WEB containers need access, but we might also have other groups, like health checks, or operations dashboards that also need access.

Create a file `APP-rules.json` with the following contents.

    {
      "id": "APP", 
      "inbound_rules": [
        {
          "action": "allow",
          "protocol": "tcp", 
          "dst_ports": [7890],
          "src_tag": "APP_7890"
        }, 
        {
          "action": "allow", 
          "protocol": "icmp",
          "icmp_type": 8
        }
      ], 
      "outbound_rules": [
        {
          "action": "allow"
        }
      ]
    }

This grants access to port 7890 to containers with the `APP_7890` tag, and to ICMP for pings.  Update the APP profile rules.

    ./calicoctl profile APP rule update < APP-rules.json

Finally, to enable access from the WEB containers, you need to tag them with the `APP_7890` tag.

    ./calicoctl profile WEB tag add APP_7890

Verify the tag was accepted by running

    $ ./calicoctl profile WEB tag show
    WEB
    APP_7890

