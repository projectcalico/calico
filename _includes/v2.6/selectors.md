A label selector is an expression which either matches or does not match an endpoint based on its labels.

Calico label selectors support a number of syntactic primitives.  Each of the following 
primitive expressions can be combined using the logical operator `&&`.

| Syntax              | Meaning                     |
|---------------------|-----------------------------|
| k == 'v'            | Matches any endpoint with the label 'k' and value 'v'.
| k != 'v'            | Matches any endpoint with the label 'k' and value that is _not_ 'v'.
| has(k)              | Matches any endpoint with label 'k', independent of value.
| !has(k)             | Matches any endpoint that does not have label 'k'
| k in { 'v1', 'v2' } | Matches any endpoint with label 'k' and value in the given set
| k not in { 'v1', 'v2' } | Matches any endpoint without label 'k' or any with label 'k' and value _not_ in the given set


