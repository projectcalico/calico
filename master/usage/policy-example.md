---
title: Realistic Policy Demo
---

Three-tier application: frontend, backend, database
Three groups: Dev, Test, Prod

![yada](/images/sample-app-policy.png)

Sample labels:

```json
{
  "app": "frontend",
  "group": "dev"
}
```

## Application Policy

```yaml
---
apiVersion: v1
kind: policy
metadata:
  name: frontend
spec:
  order: 100
  selector: role == 'frontend'
  ingress:
  - action: allow
    protocol: tcp
    destination:
      ports:
      - 8080
  egress:
  - action: allow
    destination:
      selector: role == 'backend'
      ports:
      - 9090
---
apiVersion: v1
kind: policy
metadata:
  name: backend
spec:
  order: 100
  selector: role == 'backend'
  ingress:
  - action: allow
    protocol: tcp
    source:
      selector: role == 'frontend'
    destination:
      ports:
      - 8080
  egress:
  - action: allow
    destination:
      selector: role == 'database'
      ports:
      - 6379
---
apiVersion: v1
kind: policy
metadata:
  name: database
spec:
  order: 100
  selector: role == 'database'
  ingress:
  - action: allow
    protocol: tcp
    source:
      selector: role == 'backend'
    destination:
      ports:
      - 6379
  egress:
  - action: deny
```

Notice that we've chosen `order: 100`. For our next policy to apply _before_ this,
we'll specify a lower order of 50.

## Base Policy

```yaml
---
apiVersion: v1
kind: policy
metadata:
  name: dev
spec:
  order: 50
  selector: group == 'dev'
  ingress:
  - action: deny
    source:
      selector: group != 'dev'
  egress:
  - action: deny
    destination:
      selector: group != 'dev'
---
apiVersion: v1
kind: policy
metadata:
  name: staging
spec:
  order: 50
  selector: group == 'staging'
  ingress:
  - action: deny
    source:
      selector: group != 'staging'
  egress:
  - action: deny
    destination:
      selector: group != 'staging'
---
apiVersion: v1
kind: policy
metadata:
  name: prod
spec:
  order: 50
  selector: group == 'prod'
  ingress:
  - action: deny
    source:
      selector: group != 'prod'
  egress:
  - action: deny
    destination:
      selector: group != 'prod'
```
