An EndpointPort associates a name with a particular TCP/UDP/SCTP port of the endpoint, allowing it to
be referenced as a named port in [policy rules](./networkpolicy#entityrule).

| Field    | Description                                                                                                                                            | Accepted Values      | Schema | Default  |
|----------|--------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------|--------|----------|
| name     | The name to attach to this port, allowing it to be referred to in [policy rules](./networkpolicy#entityrule). Names must be unique within an endpoint. |                      | string |          |
| protocol | The protocol of this named port.                                                                                                                       | `TCP`, `UDP`, `SCTP` | string |          |
| port     | The workload port number.                                                                                                                              | `1`-`65535`          | int    |          |

> **Note**: On their own, EndpointPort entries don't result in any change to the connectivity of the port.
> They only have an effect if they are referred to in policy.
{: .alert .alert-info}
