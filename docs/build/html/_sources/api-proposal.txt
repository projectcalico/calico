Calico API Design
=================

*Author's Note: This is a work in progress with some known issues. If
something in this document strikes you as odd, please consult the list
of outstanding issues at the bottom of the document before commenting.
However, if it's not already mentioned, please do comment through our
`mailing list <http://lists.projectcalico.org/listinfo/calico>`__ and
`community <http://www.projectcalico.org/community/>`__. Feedback is
welcomed!*

A simplified diagram of the current Calico architecture plan looks like
this:

.. figure:: _static/calico_API_arch_Sept_2014.png
   :alt: The Calico Architecture

   The Calico Architecture

More information on the components of this architecture can be found
in :doc:`arch-felix-and-acl`.
This document covers the concepts used in the three APIs shown in the
above diagram.

The Calico API is conceptually divided into three parts: the Calico
Endpoint API, the Calico ACL API, and the Calico Network API. Each
portion communicates different information. The Calico Endpoint API
communicates data *about* endpoints (such as their IP addresses, MAC
addresses and so on), as well as for endpoint discovery. The Calico ACL
API communicates the state of ACLs for a given endpoint. The Calico
Network API communicates the virtual network topology to the ACL
manager.

Felix (or other agents) implements both the Endpoint API and the ACL
API. The Calico Plugin (or the orchestration system, if Calico is
deployed directly into the system) implements the Endpoint API. The
Calico ACL Manager (or any component replacing it) implements the ACL
API and the Network API.

Each of these APIs is given separate treatment below.

General API Format
------------------

Each API endpoint details a *type* and a *body*. The body of each
message is JSON-formatted. The *body* section of each API endpoint
document lists all the fields that are in the message body. These fields
are all mandatory and may not be ``null`` unless explicitly mentioned.
In addition to the *body* fields, each message body must also include
its *type*.

Calico Endpoint API
-------------------

The Calico Endpoint API communicates information about endpoints and
notifies components about the state of individual endpoints.

This API is based on a request-response model, but *not* a client-server
model. Requests and responses can flow in either direction, depending on
the particular orchestration system being used.

The Calico Endpoint API is transported using ZeroMQ's REQ-REP socket
logic. Each peer involved SHOULD have one sending (REQ or DEALER) socket
and one receiving (REP or ROUTER) socket. Each peer MUST accept requests
from any number of peers. Each peer MAY send requests to any number of
peers (to balance load or perform HA function), but there is no
requirement to do so.

Stories
~~~~~~~

The following stories provide a high-level overview of the kinds of
messages that are passed on the Endpoint API. They are not intended as
an exhaustive enumeration of everything that can possibly be done on the
Endpoint API but as a useful guideline.

Story 1: Endpoint Creation
^^^^^^^^^^^^^^^^^^^^^^^^^^

This story covers the case where a new endpoint is to be programmed in
an environment where the Calico Plug-in is responsible for endpoint
creation. The flow is approximately as follows:

1. A new endpoint is created by a user.

2. The Calico Plug-in is informed of the endpoint creation event. It
   collates all the data associated with the endpoint creation and
   bundles it together into an "ENDPOINTCREATED" request, which it sends
   to one of the registered Felixes:

   ::

       {
         "type": "ENDPOINTCREATED",
         "endpoint_id": "a935e8e1-008a-4e05-af4b-4b5701df417e",
         "interface_name": "tapa935e8e1-00",
         "addrs": [
           {"addr": "10.0.65.2", "gateway": "10.65.0.1", "properties": {"gr": false}},
         ],
         "mac": "00:11:22:33:44:55",
         "state": "enabled",
         "resync_id": null,
         "issued": 1410276720.54
       }

3. Felix receives the message and locates the interface. It then
   programs the routing layers appropriately and sets up the necessary
   control structures. It sends the "ENDPOINTCREATED" response:

   ::

       {
         "type": "ENDPOINTCREATED",
         "rc": "SUCCESS",
         "message": ""
       }

Story 2: Endpoint State Update
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Calico Plug-in may decide at any time to disable an endpoint. When
that is done Felix should remove that endpoint from any networks in
which it is present, and may take this opportunity to simplify its own
internal state. In essence, the interface will be left present and
managed by Felix, but no programming will be entered into the system
(i.e. the route will not be advertised).

This occurs as follows:

1. The user deactivates their endpoint (e.g. to take a filesystem
   snapshot).

2. The Calico Plug-in is informed of the endpoint deactivation event. It
   sends the Felix that manages the endpoint an "ENDPOINTUPDATED"
   request, as follows:

   ::

       {
         "type": "ENDPOINTUPDATED",
         "endpoint_id": "a935e8e1-008a-4e05-af4b-4b5701df417e",
         "addrs": [
           {"addr": "10.0.65.2", "gateway": "10.65.0.1", "properties": {"gr": false}},
         ],
         "mac": "00:11:22:33:44:55",
         "state": "disabled",
         "issued": 1410276720.54
       }

3. Felix receives the message. If any programming is present on the
   system, it removes it. It keeps track of the interface itself, and
   continues to include it in any list of managed interfaces. It sends a
   response:

   ::

       {
         "type": "ENDPOINTUPDATED",
         "rc": "SUCCESS",
         "message": ""
       }

4. Some time later, the user re-activates the endpoint. The Calico
   Plug-in sends a new "ENDPOINTUPDATED" message:

   ::

       {
         "type": "ENDPOINTUPDATED",
         "endpoint_id": "a935e8e1-008a-4e05-af4b-4b5701df417e",
         "addrs": [
           {"addr": "10.0.65.2", "gateway": "10.65.0.1", "properties": {"gr": false}},
         ],
         "mac": "00:11:22:33:44:55",
         "state": "enabled",
         "issued": 1410276720.54
       }

More generally, this exact mechanism can be used whenever any property
of the endpoint is changed. It allows for on-the-fly remapping of
endpoint IP addresses, without any requirement to deactivate the
endpoint.

Story 3: Failed Endpoint Allocation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As an elaboration on Story 1, the Calico Plug-in may attempt to create
an endpoint, but Felix may encounter an error condition. In this case,
the following flow occurs:

1. A new endpoint is created by a user.

2. The Calico Plug-in is informed of the endpoint creation event. It
   collates all the data associated with the endpoint creation and
   bundles it together into an "ENDPOINTCREATED" request, which it sends
   to one of the registered Felixes:

   ::

       {
         "type": "ENDPOINTCREATED",
         "endpoint_id": "a935e8e1-008a-4e05-af4b-4b5701df417e",
         "interface_name": "tapa935e8e1-00",
         "addrs": [
           {"addr": "10.0.65.2", "gateway": "10.65.0.1", "properties": {"gr": false}},
         ],
         "mac": "00:11:22:33:44:55",
         "state": "enabled",
         "resync_id": null,
         "issued": 1410276720.54
       }

3. Felix receives the message and locates the interface. An immediate
   error occurs (for example, Felix cannot locate the interface), and it
   reports the error back:

   ::

       {
         "type": "ENDPOINTCREATED",
         "rc": "ENOINTERFACE",
         "message": "Unable to locate interface: permission denied"
       }

   Note that if Felix is not running (for example, because it has failed
   or been manually stopped) then the Calico Plug-in treats the lack of
   a timely response as a failure.

4. The Calico Plug-in must then handle this failure. For example, in the
   OpenStack case, the behavior is to report the error back to
   ``neutron`` which then marks the endpoint as failed, and retries as
   appropriate; other Plug-ins may choose to behave differently.

Detailed API Description
~~~~~~~~~~~~~~~~~~~~~~~~

Request-Response
^^^^^^^^^^^^^^^^

Request: ENDPOINTCREATED
''''''''''''''''''''''''

-  **Type**: ``ENDPOINTCREATED``
-  **Direction**: Plugin → Felix
-  **Body**: An ``ENDPOINTCREATED`` request has the following properties
   in its body:

   -  *endpoint\_id*: A UUID4 uniquely identifying the endpoint.
   -  *interface\_name*: The name of the interface; for example, in
      OpenStack this can be constructed by taking the first 11
      characters of the endpoint\_id and prepending the string "tap".
   -  *addrs*: A list of all IP addresses assigned to this particular
      endpoint in the IP Address format described below.
   -  *mac*: The MAC address of the interface assigned to the endpoint.
      This MAC address is not visible to other machines in the data
      center (as Calico virtualises networks at layer 3), but is used to
      prevent MAC spoofing.
   -  *state*: The state of the endpoint. A string with two possible
      values, "enabled" and "disabled". A endpoint that is "enabled" is
      reachable on its virtual network: an endpoint that is "disabled"
      is not.
   -  *resync\_id*: The ID number of the "RESYNCSTATE" message which
      triggered this message. It is only used when a Felix instance has
      requested state resynchronisation, and is used to disambiguated
      messages that are triggered by such a request from other
      ENDPOINTCREATED messages. Should be ``null`` if this message is
      not triggered by a "RESYNCSTATE" message.
   -  *issued*: A unix timestamp with millisecond or better precision
      corresponding to the time the request was issued.

This request is an indication that the plugin or orchestrator has
created a new endpoint, and is instructing this Felix to manage its
networking. It is used both to request endpoint creation, and is used in
all systems to carry data about an endpoint if Felix has requested state
resynchronisation (see the "RESYNCSTATE" message below).

When state resynchronisation is in progress, no ``ENDPOINTCREATED``
messages for new endpoint creation (i.e. with *resnyc\_id* equal to
``null``) can be sent until the state resynchronisation has completed.

Response: ENDPOINTCREATED
'''''''''''''''''''''''''

-  **Type**: ``ENDPOINTCREATED``
-  **Direction**: Felix → Plugin
-  **Body**: An ``ENDPOINTCREATED`` response has the following
   properties in its body:

   -  *rc*: A return code, as a string. The list of valid return codes
      is provided as an appendix to this document.
   -  *message*: A free-form text field containing extra diagnostic
      information about the response. Generally expected to be empty on
      success.

This response reports whether the endpoint creation is possible. In some
situations Felix may know that it cannot create an endpoint (e.g.
because of some systemic server failure, or an internal error in Felix).
Felix can use the error code in this message to report that status to
the plugin.

Note that this response is returned almost immediately after the
request: Felix does not wait for the interface to be fully programmed.
This would take too long. This means that errors encountered in the
interface creation process are not reported on this interface.

Request: ENDPOINTUPDATED
''''''''''''''''''''''''

-  **Type**: ``ENDPOINTUPDATED``
-  **Direction**: Plugin → Felix
-  **Body**: A ``ENDPOINTUPDATED`` request has the following properties
   in its body:

   -  *endpoint\_id*: A UUID4 uniquely identifying the endpoint. Felix
      must be able to determine the name of the tap interface from this
      UUID by taking the first 9 characters of the UUID and prepending
      the string "tap".
   -  *addrs*: A list of all IP addresses assigned to this particular
      endpoint in the IP Address format described below.
   -  *mac*: The MAC address of the interface assigned to the endpoint.
      This MAC address is not visible to other machines in the data
      center (as Calico virtualises networks at layer 3), but is used to
      prevent MAC spoofing.
   -  *state*: The state of the endpoint. A string with two possible
      values, "enabled" and "disabled". A endpoint that is "enabled" is
      reachable on its virtual network: an endpoint that is "disabled"
      is not.
   -  *issued*: A unix timestamp with millisecond or better precision
      corresponding to the time the request was issued.

This request asks Felix to update the state of a given endpoint. Any of
the body fields (aside from *issued*) may be changed from the current
state of the endpoint and Felix will update the configuration to reflect
the change.

Response: ENDPOINTUPDATED
'''''''''''''''''''''''''

-  **Type**: ``ENDPOINTUPDATED``
-  **Direction**: Felix → Plugin
-  **Body**: A ``ENDPOINTUPDATED`` response has the following properties
   in its body:

   -  *rc*: A return code, as a string. The list of valid return codes
      is provided as an appendix to this document.
   -  *message*: A free-form text field containing extra diagnostic
      information about the response. Generally expected to be empty on
      success.

This response reflects whether Felix was capable of updating the
configuration. In practice, this can never fail.

Request: ENDPOINTDESTROYED
''''''''''''''''''''''''''

-  **Type**: ``ENDPOINTDESTROYED``
-  **Direction**: Plugin → Felix
-  **Body**: A ``ENDPOINTDESTROYED`` request has the following
   properties in its body:

   -  *endpoint\_id*: The UUID4 uniquely identifying the endpoint to
      destroy.
   -  *issued*: A unix timestamp with millisecond or better precision
      corresponding to the time the request was issued.

This request asks Felix to destroy an endpoint. It instructs Felix to
permanently remove all configuration for an interface, and to stop
managing it.

Response: ENDPOINTDESTROYED
'''''''''''''''''''''''''''

-  **Type**: ``ENDPOINTDESTROYED``
-  **Direction**: Felix → Plugin
-  **Body**: A ``ENDPOINTDESTROYED`` request has the following
   properties in its body:

   -  *rc*: A return code, as a string. The list of valid return codes
      is provided as an appendix to this document.
   -  *message*: A free-form text field containing extra diagnostic
      information about the response. Generally expected to be empty on
      success.

This response reflects whether Felix was capable of removing the
configuration. In practice, this may never fail.

Request: RESYNCSTATE
''''''''''''''''''''

-  **Type**: ``RESYNCSTATE``
-  **Direction**: Felix → Plugin
-  **Body**: A ``RESYNCSTATE`` request has the following properties in
   its body:

   -  *resync\_id*: A unique string identifier for this state
      resychronisation request. This identifier will be included on all
      the triggered ``ENDPOINTCREATED`` messages, and can be used to
      identify them.
   -  *issued*: A unix timestamp with millisecond or better precision
      corresponding to the time the request was issued.
   -  *hostname*: The hostname of the Felix issuing the request.

A ``RESYNCSTATE`` message is issued whenever a Felix is started in a
plugin-led environment, and is only valid in such an environment. The
request causes the Plugin to re-issue all the ``ENDPOINTCREATED``
messages required to re-establish Felix state. This allows for Felix to
get into a correct state if for any reason it encounters an error or is
restarted.

Please note that ``RESYNCSTATE`` is *not* intended to allow the Plugin
to process new endpoint creations successfully at a time when it is not
connected to a Felix on the relevant compute host, on the assumption
that the required Felix may shortly appear and connect to the Plugin. In
such a scenario, the Plugin should choose another compute host instead,
for which it does have an active Felix connection, or fail the endpoint
creation if no suitable compute hosts are available.

Response: RESYNCSTATE
'''''''''''''''''''''

-  **Type**: ``RESYNCSTATE``
-  **Direction**: Plugin → Felix
-  **Body**: A ``RESYNCSTATE`` response has the following properties in
   its body:

   -  *endpoint\_count*: The number of ``ENDPOINTCREATED`` messages
      Felix should expect to receive in response to its request.
   -  *interface\_prefix*: The interface prefix. To identify which
      endpoints it manages, Felix needs to know the unique starting
      prefix (such as "tap" or "veth") for all interface names passed on
      ``ENDPOINTCREATED`` messages, and this is where that information
      is supplied.
   -  *rc*: A return code indicating whether the Plugin is able to
      rebuild the Felix state.
   -  *message*: A free-form text field containing extra diagnostic
      information about the response. Generally expected to be empty on
      success.

Request: HEARTBEAT
''''''''''''''''''

-  **Type**: ``HEARTBEAT``
-  **Direction**: Plugin → Felix
-  **Body**: A ``HEARTBEAT`` request has no body.

Response: HEARTBEAT
'''''''''''''''''''

-  **Type**: ``HEARTBEAT``
-  **Direction**: Felix → Plugin
-  **Body**: A ``HEARTBEAT`` response has no body.

The ``HEARTBEAT`` request is sent from the plugin to Felix if the
connection between the two has been inactive for 30 seconds. It, along
with its response, allows the plugin and Felix to confirm that the
connection between them is still active.

Structures
^^^^^^^^^^

This section contains any data structures referenced in the above
documentation. For a data structure to be in this section it must be
sufficiently complex that it would interfere with the clarity of the
previous section.

Object: IP Address
''''''''''''''''''

An "IP Address" structure represents a single IP address assigned to an
endpoint. It takes the following form:

::

    {
      "addr": <an IPv4 or IPv6 address, as a string>
      "gateway": <the IPv4 or IPv6 address for the default gateway for this address, as a string>,
      "properties": <a key-value list of properties assigned to this address>
    }

The *addr* and *gateway* values must both be the same kind of IP
address: it is an error to send a message with different address types
for the endpoint and the gateway in a single "IP Address" structure.

The *properties* key-value list defines all the properties assigned to a
single address. This is defined in an extensible format to allow
non-Felix agents to act on properties unique to a given operator. Felix
understands the following properties:

-  *gr*: Whether the address is globally routable (i.e. reachable from
   outside the data center). Must be one of ``true`` or ``false``. If
   absent, defaults to ``false``.

Calico ACL API
--------------

The Calico ACL API communicates information about ACLs and notifies
components about changes to the deployment-wide ACL configuration.

This API is based on a combination request-response and
publish-subscribe model. The request-response portion of the API is used
for one-off synchronisation between Felix and the ACL manager, while the
publish-subscribe model is used for longer-term monitoring of changes to
ACL state. Requests can only flow from Felix to the ACL manager. The ACL
manager is the only entity that can publish: Felixes subscribe.

This API is transported by ZeroMQs REQ-REP and PUB-SUB socket logic.
Each Felix MUST have one sending (REQ or DEALER) socket. The ACL manager
must have one receiving (REP or ROUTER) socket, from which it will
accept connections from any number of Felixes. Additionally, each Felix
MUST have one SUB socket, and the ACL manager MUST have one PUB socket.

Stories
~~~~~~~

The following stories provide a high-level overview of the kinds of
messages that are passed on the ACL API. They are not intended as an
exhaustive enumeration of everything that can possibly be done on the
ACL API but as a useful guideline.

Story 1: ACLs for a New Endpoint
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this situation, Felix is provisioning a new endpoint. It needs a
snapshot of the current ACL state for that endpoint. It fetches this
information from the ACL manager using a request-response cycle.
Separately, it also subscribes to ACL updates for that endpoint.

1. Felix issues a "GETACLSTATE" request to the ACL manager, passing the
   interface ID of the endpoint.

   ::

       {
         "type": "GETACLSTATE",
         "endpoint_id": "a935e8e1-008a-4e05-af4b-4b5701df417e",
         "issued": 1410276720.54
       }

2. The ACL manager determines that the request is for a valid endpoint,
   and then returns success.

   ::

       {
         "type": "GETACLSTATE",
         "endpoint_id": "a935e8e1-008a-4e05-af4b-4b5701df417e",
         "rc": "SUCCESS",
         "message": ""
       }

3. The ACL manager looks up the current state of the ACLs on the system.
   It builds them into a form suitable for sending back to Felix, and
   then immediately publishes them in an "ACLUPDATE" subscription to the
   subscription whose name is the UUID of the affected endpoint.

   ::

       {
         "type": "ACLUPDATE",
         "acls": <ACL rules>,
         "issued": 1410276720.54
       }

Story 2: A change in ACL state of an endpoint
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this situation, an endpoint has had its ACL state changed (e.g.
security group rules have changed, or a new machine has been added to a
security group or network). The ACL manager has calculated the new ACL
state, and determined which machines are affected. The following flow
occurs.

1. The ACL manager publishes an "ACLUPDATE" message to the subscription
   whose name is the UUID of the affected endpoint.

   ::

       {
         "type": "ACLUPDATE",
         "acls": <ACL rules>,
         "issued": 1410276720.54
       }

   This message contains the full set of ACL rules for that endpoint,
   *not* a delta. This is both for simplicity and to allow eventual
   resynchronisation of state over time.

Detailed API Description
~~~~~~~~~~~~~~~~~~~~~~~~

Request-Response
^^^^^^^^^^^^^^^^

Request: GETACLSTATE
''''''''''''''''''''

-  **Type**: ``GETACLSTATE``
-  **Direction**: Felix → ACL Manager
-  **Body**: A ``GETACLSTATE`` request contains the fillowing fields in
   its body:

   -  *endpoint\_id*: The UUID4 representing the endpoint whose ACLs
      Felix is requesting.
   -  *issued*: A Unix timestamp with millisecond or better resolution
      indicating when the request was issued.

Response: GETACLSTATE
'''''''''''''''''''''

-  **Type**: ``GETACLSTATE``
-  **Direction**: ACL Manager → Felix
-  **Body**: A ``GETACLSTATE`` response contains the following fields in
   its body:

   -  *endpoint\_id*: The UUID4 representing the endpoint whose ACLs
      have been requested.
   -  *rc*: A return code indicating whether the ACL manager is going to
      publish the current ACL state.
   -  *message*: A free-form text field carrying extra diagnostic
      information about the response. Generally expected to be empty on
      success.

Pub-Sub
^^^^^^^

Publication: ACLUPDATE
''''''''''''''''''''''

-  **Type**: ``ACLUPDATE``
-  **Direction**: ACL Manager → Felix
-  **Body**: An ``ACLUPDATE`` publication contains the following fields:

   -  *acls*: An ACL collection object, as detailed below.
   -  *issued*: A Unix timestamp with millisecond or better precision
      indicating when the publication was issued.

There is one ``ACLUPDATE`` subscription per endpoint in the network,
with the subscription name being set to the UUID of the endpoint. Each
time the ACL state of the endpoint changes an ``ACLUPDATE`` publication
is issued on that subscription, containing the complete ACL state of the
endpoint. These messages may also be triggered by a ``GETACLSTATE``
request, which will cause the ACL manager to immediately publish the
current state of ACLs for that endpoint on the relevant subscription.

Publication: HEARTBEAT
''''''''''''''''''''''

-  **Type**: ``HEARTBEAT``
-  **Direction**: ACL Manager → Felix
-  **Body**: An ``HEARTBEAT`` publication contains the following fields:

   -  *issued*: A Unix timestamp with millisecond or better precision
      indicating when the heartbeat was issued.

Each Calico network has a single ``aclheartbeat`` subscription running
between the ACL manager and all the Felices. This subscription never has
ACLs published on it. Instead, every 30 seconds the ACL manager
publishes a single heartbeat message.

Structures
^^^^^^^^^^

This section contains any data structures referenced in the above
documentation. For a data structure to be in this section it must be
sufficiently complex that it would interfere with the clarity of the
previous section.

Object: ACL collection
''''''''''''''''''''''

An *ACL collection* represents a group of ACLs. It takes the following
form:

::

    {
      "v4": <rules object>,
      "v6": <rules object>
    }

The ACLs in the "v4" key apply to IPv4 traffic, the ACLs in the "v6" key
apply to IPv6 traffic.

The *rules* objects mentioned here are defined in the section relating
to the Network API later in this document.

Calico Network API
------------------

The Calico Network API communicates information about the network
topology of a given Calico deployment. This communication runs between
the Calico Plugin and the Calico ACL manager.

This API transfers the following information:

-  which security groups exist
-  the security group rules
-  which security groups endpoints belong to

This API is based on a combination request-response and
publish-subscribe model. The request-response portion of the API is used
to initiate one-off synchronisation between the plugin and the ACL
manager, while the publish-subscribe model is used for monitoring of
state changes. Requests can only flow from the ACL manager to the
plugin. The plugin is the only entity that can publish: the ACL manager
subscribes.

This API is transported by ZeroMQs REQ-REP and PUB-SUB socket logic. The
ACL manager MUST have one sending (REQ or DEALER) socket. The Plugin
must have one receiving (REP or ROUTER) socket, from which it will
accept connections from the ACL manager. Additionally, the ACL manager
MUST have one SUB socket, and the plugin MUST have one PUB socket.

Stories
~~~~~~~

*Note: There are relatively few stories here because by and large they
all take the same form: subscribe to some state and get told when it
changes, and ask for all the current state.*

Story 1: Initial Configuration Update
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This flow can occur when the ACL manager starts up after the Calico
plugin is already running: for example, turning up a new machine or
recovering from machine failure. In this case the ACL manager needs to
resynchronize with the plugin to learn all the applicable state. The
following events occur:

1. The ACL manager starts up.
2. It determines that it needs to work out the state of the network, and
   so it issues a "GETGROUPS" message:

   ::

       {
         "type": "GETGROUPS",
         "issued": 1410276720.54
       }

3. The Calico plugin receives the message. It immediately returns a
   simple response:

   ::

       {
         "type": "GETGROUPS",
         "rc": "SUCCESS",
         "message": ""
       }

4. The Calico plugin now checks its internal state to find all the
   security groups in the system. For each group it issues a
   "GROUPUPDATE" message on the ``groups`` subscription containing the
   information about that security group:

   ::

       {
         "type": "GROUPUPDATE",
         "group": <the UUID of the security group being updated>,
         "rules": <a rules object as shown below>,
         "members": <a members object as shown below>,
         "issued": 1410276720.54
       }

Story 2: Security Group Rules Change
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

While the system is enabled a user may change the rules that apply to a
security group. This rules change needs to propagate into the ACL
manager so that it can update its state and, if necessary, notify the
Felix agents of configuration changes that need to be made. When a user
changes security group rules, the following events occur:

1. The user changes some security group rules.
2. The Calico plugin detects the change in security group rules and
   issues a new message on the "groups" subscription, with type
   "GROUPUPDATE":

   ::

       {
         "type": "GROUPUPDATE",
         "group": <the UUID of the security group being updated>,
         "rules": <a rules object as shown below>,
         "members": <a members object as shown below>,
         "issued": 1410276720.54
       }

   This message includes the full security group rules state after the
   change: it does *not* encode deltas.

3. The ACL manager receives this set of changed security group rules. It
   updates it internal state and recalculates any necessary rule
   changes. If it finds this change affects connectivity it notifies the
   relevant Felixes to update the state they program into the kernel.

Detailed API Description
~~~~~~~~~~~~~~~~~~~~~~~~

Request-Response
^^^^^^^^^^^^^^^^

Request: GETGROUPS
''''''''''''''''''

-  **Type**: ``GETGROUPS``
-  **Direction**: ACL Manager → Plugin
-  **Body**: The body of a ``GETGROUPS`` request contains the following
   fields:

   -  *issued*: A Unix timestamp with millisecond or better precision
      indicating when the request was issued.

Response: GETGROUPS
'''''''''''''''''''

-  **Type**: ``GETGROUPS``
-  **Direction**: Plugin → ACL Manager
-  **Body**: The body of a ``GETGROUPS`` response contains the following
   fields:

   -  *rc*: A return code indicating whether the plugin is going to
      publish the current security group state.
   -  *message*: A free-form text field carrying extra diagnostic
      information about the response. Generally expected to be empty on
      success.

The ``GETGROUPS`` request-response pair is used to provide one-off
resynchronisation of the current collection of security groups in the
system, including which machines are in which security groups. This
resynchronisation is actually achieved over the Pub-Sub interface: this
message simply triggers that set of messages.

Pub-Sub
^^^^^^^

Publication: GROUPUPDATE
''''''''''''''''''''''''

-  **Type**: ``GROUPUPDATE``
-  **Direction**: Plugin → ACL Manager
-  **Body**: The body of a ``GROUPUPDATE`` publication contains the
   following fields:

   -  *rules*: A single *rules* object as detailed below. The ``group``
      keys within this *rules* object MUST be set to ``null``.
   -  *group*: The UUID of the security group being updated.
   -  *members*: A single *members* object as detailed below.
   -  *issued*: A Unix timestamp with millisecond or better precision
      indicating when the request was issued.

The ``GROUPUPDATE`` publication is only ever issued on the ``groups``
subscription. It is issued whenever rules in a security group are
changed, and contains the entire rules state for that security group,
including the rules and memberships.

This message is also issued to notify the ACL manager about new security
groups, and to inform it of whem a security group has been removed. New
security groups are notified simply by sending a notification of their
rules and members. The removal of a security group is notified by
sending a ``GROUPUPDATE`` for the group with an empty *members* object.
Security groups without members have no effect on the security topology
and can be considered non-existent.

This message is *not* segmented into multiple subscriptions, one per
group, the way endpoint ACLs are on the ACL API. This is because we do
not believe that there will be any case where a subscriber of the ACL
API will not want *all* security group rule changes.

Publication: HEARTBEAT
''''''''''''''''''''''

-  **Type**: ``HEARTBEAT``
-  **Direction**: Plugin → ACL Manager
-  **Body**: An ``HEARTBEAT`` publication contains the following fields:

   -  *issued*: A Unix timestamp with millisecond or better precision
      indicating when the heartbeat was issued.

Each Calico network has a single ``networkheartbeat`` subscription
running between the plugin and all the ACL manager. This subscription
never has data published on it. Instead, every 30 seconds the plugin
publishes a single heartbeat message.

This can be used by the ACL manager to determine whether the plugin is
present and the subscription connection is active.

Structures
^^^^^^^^^^

This section contains any data structures referenced in the above
documentation. For a data structure to be in this section it must be
sufficiently complex that it would interfere with the clarity of the
previous section.

Object: security groups
'''''''''''''''''''''''

The *security groups* object contains a mapping of all security groups
present on the deployment to the endpoints that are in that security
group. This is represented by a JSON object whose keys are security
group UUIDs and whose values are lists of endpoint UUIDs. Each list
element in the value is an endpoint that is present in a security group.

Object: rules
'''''''''''''

The *rules* object contains all of the security group rules associated
with a group. This has the following form:

::

    {
      "inbound": <list of rule objects>,
      "outbound": <list of rule objects>,
      "inbound_default": "deny",
      "outbound_default": "deny"
    }

Each rule object is detailed below. Each rule represents an *exception*
to the default policy for that direction, which may be which may only
contain the value "deny". For this object, "inbound" represents
connections coming *to* an endpoint, and "outbound" means connections
coming *from* an endpoint.

Object: rule
''''''''''''

A single *rule* object represents one security group rule. It's a JSON
object with the following keys:

-  *group*: This rule allows/denies connections coming to/from a
   specific security group. If the *cidr* key is present, this key MUST
   be ``null``.
-  *cidr*: This rule allows/denies connections coming to/from a specific
   subnet. If the *group* key is present, ths key MUST be ``null``.
-  *protocol*: The network protocol (e.g. "udp"). To match all
   protocols, send ``null``.
-  *port*: This rule only affects traffic to/from this port. Should be a
   JSON number, or the ``null`` (meaning all ports). Must be ``null``
   for protocols that do not have ports (e.g. ICMP).

Below are some example rules:

::

    {"group": null, "cidr": "10.65.0.0/24", "protocol": null, "port:": null}

This rule matches all traffic to/from the 10.65.0.0/24 subnet, in all
protocols, to all ports.

::

    {"group": "a935e8e1-008a-4e05-af4b-4b5701df417e", "cidr": null, "protocol": null, "port": null}

This rule matches all traffic to/from a specific security group.

::

    {"group": null, "cidr": "0.0.0.0/0", "protocol": "tcp", "port": "80"}

This rule matches all TCP traffic to/from any source to port 80.

Object: members
'''''''''''''''

The *members* object contains all of the endpoints belonging to a
specific security group. It takes the form of a key-value set, where the
keys are the IDs of the endpoints in the security group and the values
are the IP addresses associated with that endpoint.

::

    {
      "<endpoint ID>": <list of IP addresses>,
      ...
    }

There is no requirement that each endpoint be in only one security
group, they may be in multiple groups.

Return Codes
------------

The following is a list of specified return codes for the API:

-  "SUCCESS"

Known Issues
------------

-  We will at some point want a liveness API from Felix. This will be
   dealt with in a later revision of the API.
-  We need to extend the Endpoint API and ACL API to handle the fact
   that a single endpoint may be associated with multiple ports, and
   that a single port may be associated with multiple endpoints (e.g.
   with Cumulus). Right now this is not adequately handled in this API.

