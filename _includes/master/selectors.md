A label selector is an expression which either matches or does not match a resource based on its labels.

{{site.prodname}} label selectors support a number of syntactic primitives.  Each of the following
primitive expressions can be combined using the logical operator `&&` and `||`.

| Syntax              | Meaning                     |
|---------------------|-----------------------------|
| all()               | Match all resources.
| k == 'v'            | Matches any resource with the label 'k' and value 'v'.
| k != 'v'            | Matches any resource with the label 'k' and value that is _not_ 'v'.
| has(k)              | Matches any resource with label 'k', independent of value.
| !has(k)             | Matches any resource that does not have label 'k'
| k in { 'v1', 'v2' } | Matches any resource with label 'k' and value in the given set
| k not in { 'v1', 'v2' } | Matches any resource without label 'k' or any with label 'k' and value _not_ in the given set
| k contains 's'      | Matches any resource with label 'k' and value containing the substring 's'
| k starts with 's'   | Matches any resource with label 'k' and value starting with the substring 's'
| k ends with 's'     | Matches any resource with label 'k' and value ending with the substring 's'


