{{site.prodname}} supports the following syntaxes for expressing ports.

| Syntax     | Example    | Description |
|------------|------------|-------------|
| int        | 80         | The exact (numeric) port specified 
| start:end  | 6040:6050  | All (numeric) ports within the range start <= x <= end
| string     | named-port | A named port, as defined in the ports list of one or more endpoints

An individual numeric port may be specified as a YAML/JSON integer.  A port range or
named port must be represented as as a string.  For example, this would be a valid list of ports:
```yaml
ports: [8080, "1234:5678", "named-port"]
```

##### Named ports

Using a named port in an `EntityRule`, instead of a numeric port, gives a layer of indirection, 
allowing for the named port to map to different numeric values for each endpoint.  

For example, suppose you have multiple HTTP servers running as workloads; some exposing their HTTP 
port on port 80 and others on port 8080. In each workload, you could create a named port called 
`http-port` that maps to the correct local port.  Then, in a rule, you could refer to the name 
`http-port` instead of writing a different rule for each type of server.

> **NOTE**: Since each named port may refer to many endpoints (and {{site.prodname}} has to expand a named port into
> a set of endpoint/port combinations), using a named port is considerably more expensive in terms 
> of CPU than using a simple numeric port.  We recommend that they are used sparingly, only where 
> the extra indirection is required.
{: .alert .alert-info}
