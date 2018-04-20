
Here is an example of how you can secure the Felix-Typha communications in your
cluster:

1.  Choose a Certificate Authority, or set up your own.

1.  Obtain or generate the following leaf certificates, signed by that
    authority, and corresponding keys:

    -  A certificate for each Felix with Common Name 'typha-client' and
       extended key usage 'ClientAuth'.

    -  A certificate for each Typha with Common Name 'typha-server' and
       extended key usage 'ServerAuth'.

1.  Configure each Typha with:

    -  `CAFile` pointing to the Certificate Authority certificate

    -  `ServerCertFile` pointing to that Typha's certificate

    -  `ServerKeyFile` pointing to that Typha's key

    -  `ClientCN` set to 'typha-client'

    -  `ClientURISAN` unset.

1.  Configure each Felix with:

    -  `TyphaCAFile` pointing to the Certificate Authority certificate

    -  `TyphaCertFile` pointing to that Felix's certificate

    -  `TyphaKeyFile` pointing to that Felix's key

    -  `TyphaCN` set to 'typha-server'

    -  `TyphaURISAN` unset.

For a [SPIFFE](https://github.com/spiffe/spiffe)-compliant deployment you can
follow the same procedure as above, except:

1.  Choose [SPIFFE
    Identities](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md#2-spiffe-identity)
    to represent Felix and Typha.

1.  When generating leaf certificates for Felix and Typha, put the relevant
    SPIFFE Identity in the certificate as a URI SAN.

1.  Leave `ClientCN` and `TyphaCN` unset.

1.  Set Typha's `ClientURISAN` parameter to the SPIFFE Identity for Felix that
    you use in each Felix certificate.

1.  Set Felix's `TyphaURISAN` parameter to the SPIFFE Identity for Typha.
