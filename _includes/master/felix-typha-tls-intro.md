
The communication between Felix and Typha instances can be secured with TLS.
This protects against:

-  a rogue or impostor Typha sending incorrect endpoint or policy information
   to the Felix instances that connect to it

-  a rogue or impostor Felix wrongly receiving privileged information about the
   overall cluster from the Typha that it connects to

-  any other process discovering privileged information about the overall
   cluster by eavesdropping on the communication channel.
