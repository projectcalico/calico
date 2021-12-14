A label selector is an expression which either matches or does not match a resource based on its labels.

{{site.prodname}} label selectors support a number of operators, which can be combined into larger expressions
using the boolean operators and parentheses. 

| Expression                | Meaning                     |
|---------------------------|-----------------------------|
| **Logical operators**     |
| `( <expression> )`        | Matches if and only if `<expression>` matches.  (Parentheses are used for grouping expressions.)
| `! <expression>`          | Matches if and only if `<expression>` does not match.  **Tip:** `!` is a special character at the start of a YAML string, if you need to use `!` at the start of a YAML string, enclose the string in quotes.
| `<expression 1> && <expression 2>` | "And": matches if and only if both `<expression 1>`, and, `<expression 2>` matches
| <code><expression 1> &#124;&#124; <expression 2></code> | "Or": matches if and only if either `<expression 1>`, or, `<expression 2>` matches.
| **Match operators**       |
| `all()`                   | Match all in-scope resources.  To match _no_ resources, combine this operator with `!` to form `!all()`.
| `global()`                | Match all non-namespaced resources.  Useful in a `namespaceSelector` to select global resources such as global network sets.
| `k == 'v'`                | Matches resources with the label 'k' and value 'v'.
| `k != 'v'`                | Matches resources without label 'k' or with label 'k' and value _not_ equal to `v`
| `has(k)`                  | Matches resources with label 'k', independent of value. To match pods that do not have label `k`, combine this operator with `!` to form `!has(k)`
| `k in { 'v1', 'v2' }`     | Matches resources with label 'k' and value in the given set
| `k not in { 'v1', 'v2' }` | Matches resources without label 'k' or with label 'k' and value _not_ in the given set
| `k contains 's'`          | Matches resources with label 'k' and value containing the substring 's'
| `k starts with 's'`       | Matches resources with label 'k' and value starting with the substring 's'
| `k ends with 's'`         | Matches resources with label 'k' and value ending with the substring 's'

Operators have the following precedence:

* **Highest**: all the match operators 
* Parentheses `( ... )`
* Negation with `!`
* Conjunction with `&&`
* **Lowest**: Disjunction with `||`

For example, the expression
```
! has(my-label) || my-label starts with 'prod' && role in {'frontend','business'}
```
Would be "bracketed" like this:
```
((!(has(my-label)) || ((my-label starts with 'prod') && (role in {'frontend','business'}))
```
It would match:
* Any resource that did not have label "my-label".
* Any resource that both:
  * Has a value for `my-label` that starts with "prod", and,
  * Has a role label with value either "frontend", or "business".

