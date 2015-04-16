 # Advanced Network Policy

Calico endpoints are assigned their network policy by configuring them with a policy profile.  In the previous examples we created profiles and assigned endpoints to them.  By default, `calicoctl profile add` adds default config to profiles so endpoints with the profile can all communicate with one another.  In this section, we look at how to customize policy profiles for more advanced policy.

## Overview

A policy profile comprises two elements: *tags* and *rules*.  

*Tags* identify different groups or sets of Calico endpoints.  A tag might represent a role or network permission, for example, you might define a tag `db_access` that represents permission to send data to your database containers on port 3590.

*Rules* are the policy statements that Calico's firewall will enforce for your endpoints.

## Worked Example

This example assumes you have a working Calico-enabled cluster, as described in [Getting Started](/GettingStarted.md)

Let's create a new profile and look at the default rules.

    ./calicoctl profile add WEB
    ./calicoctl profile WEB rule show

You should see the following output.

    Inbound rules:
       1 allow from tag WEB 
       2 deny
    Outbound rules:
       1 allow

Notice that profiles define policy for inbound packets and outbound packets separately.  This profile allows inbound traffic from other endpoints with the tag `WEB`, and denies inbound traffic from all other addresses.  It allows all outbound traffic regardless of destination.

Let's modify this profile to make it appropriate for an actual public webserver.  To modify rules, calicoctl uses a JSON format.  We can use calicoctl to output the current rules in JSON format so we have a place to start modifying.

    ./calicoctl profile WEB rule json > web-rules.json

This saves the current rules to the file `web-rules.json`.  Load up this file in a text editor.  It should look like this.

    {
      "id": "WEB", 
      "inbound_rules": [
        {
          "action": "allow", 
          "src_tag": "WEB"
        }, 
        {
          "action": "deny"
        }
      ], 
      "outbound_rules": [
        {
          "action": "allow"
        }
      ]
    }

Modify the inbound rules as follows, leaving outbound rules as is.

    {
      "id": "WEB", 
      "inbound_rules": [
        {
          "action": "allow", 
          "protocol": "tcp",
          "src_ports": [80, 443]
        }, 
        {
          "action": "allow", 
          "protocol": "icmp"
        }, 
        {
          "action": "deny"
        }
      ], 
      "outbound_rules": [
        {
          "action": "allow"
        }
      ]
    }

This will allow inbound traffic on ports 80 (http) and 443 (https), as well as allow the Internet Control and Management Protocol (ICMP) which is used for (among other things) the `ping` command.

Save the file and apply it to the profile with

    ./calicoctl profile WEB rule update < web-rules.json

If you show the rules you should see they have been applied.

    $ ./calicoctl profile WEB rule show
    Inbound rules:
       1 allow from ports [80, 443]
       2 allow icmp
       3 deny
    Outbound rules:
       1 allow

Let's say your WEB containers will need access to some backend services.  Create a profile called APP for these services.

    ./calicoctl profile add APP

For this example, let's say the APP containers present a service on port 7890.  We'll define a new tag, `APP_7890` to give containers access to this service port.  Using a tag allows us to grant and revoke access to different other profiles.  In this example, the WEB containers need access, but we might also have other groups, like health checks, or operations dashboards that also need access.

Create a file `APP-rules.json` with the following contents.

    {
      "id": "APP", 
      "inbound_rules": [
        {
          "action": "allow",
          "protocol": "tcp", 
          "src_ports": [7890],
          "src_tag": "APP_7890"
        }, 
        {
          "action": "allow", 
          "protocol": "icmp"
        }, 
        {
          "action": "deny"
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

