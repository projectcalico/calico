An HTTPMatch matches attributes of an HTTP request. The presence of an HTTPMatch clause on a Rule will cause that rule to only match HTTP traffic. Other application layer protocols will not match the rule.

Example:

```yaml
http:
  methods: ["GET", "PUT"]
  paths:
    - exact: "/projects/calico"
    - prefix: "/users"
```
{: .no-select-button}

| Field | Description | Schema |
|-------|-------------|--------|
| methods | Match HTTP methods. Case sensitive. [Standard HTTP method descriptions.](https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html){:target="_blank"} | list of strings |
| paths | Match HTTP paths. Case sensitive. | list of [HTTPPathMatch](#httppathmatch) |

#### HTTPPathMatch

| Syntax  | Example             | Description |
|---------|---------------------|-------------|
| exact   | `exact: "/foo/bar"` | Matches the exact path as written, not including the query string or fragments. |
| prefix  | `prefix: "/keys"`   | Matches any path that begins with the given prefix. |
