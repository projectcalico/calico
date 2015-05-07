#!/bin/sh
set -e
set -x


PROFILE=TEST_PROFILE
dist/calicoctl profile add $PROFILE
TAG=TEST_TAG

# Test that the profile rule update command successfully updates.
echo '{
  "id": "TEST_PROFILE",
  "inbound_rules": [
    {
      "action": "allow",
      "src_tag": "TEST_PROFILE"
    },
    {
      "action": "deny"
    }
  ],
  "outbound_rules": [
    {
      "action": "deny"
    }
  ]
}' | dist/calicoctl profile $PROFILE rule update

dist/calicoctl profile $PROFILE rule show | grep "1 deny"

# Test that adding and removing a tag works.
(! dist/calicoctl profile $PROFILE tag show | grep $TAG)
dist/calicoctl profile $PROFILE tag add $TAG
dist/calicoctl profile $PROFILE tag show | grep $TAG
dist/calicoctl profile $PROFILE tag remove $TAG
(! dist/calicoctl profile $PROFILE tag show | grep $TAG)

echo "Tests completed successfully"
