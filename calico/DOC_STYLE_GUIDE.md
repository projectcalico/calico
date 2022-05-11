# Calico documentation style guide


## Overview

We follow [_The Chicago Manual of Style_, 17th Edition](http://chicagomanualofstyle.org/), the [_Yahoo! Style Guide_](https://www.amazon.com/Yahoo-Style-Guide-Ultimate-Sourcebook/dp/031256984X), and the [Merriam-Webster dictionary](https://www.merriam-webster.com/).

This style guide contains:

- Deviations from and extensions to the primary style resources
- Clarification on frequent points of confusion
- Terminology guidelines


## Voice

The passive voice can obscure the actor and result in weak sentences.
In general, we prefer the active voice. For more information on this
topic, consult the following resources:

- [Purdue Online Writing Lab](https://owl.english.purdue.edu/owl/resource/539/02/)
- [Grammar Girl](http://www.quickanddirtytips.com/education/grammar/active-voice-versus-passive-voice)


## Pronouns

Use the second person to refer to your reader.

- **Correct**: "You must migrate your data before upgrading."
- **Incorrect**: "We need to migrate our data before upgrading."

Use the first person plural to refer to Project Calico.

- **Correct**: "We recommend five nodes."
- **Incorrect**: "Five nodes are recommended."


## Anthropomorphism

Avoid personifying software.

**Correct**:
- "Kubernetes detects that Calico is installed."
- "The delimiter specifies where to split the string."

**Incorrect**:
- "Kubernetes sees that Calico is installed."
- "The delimiter tells Calico where to split the string."


## Future features

Avoid documenting future features or products.


## Graphics

### Screenshots and animated GIFs

We discourage including screenshots and animated GIFs of web interfaces.
Such graphics are difficult to maintain, take up a lot of real estate,
and often add negligible value.

### Bitmap formats

When including a static screenshot image, use the PNG format. For animated
sequences, use GIF.

### Vector formats

For diagrams and other vector illustrations, we prefer the SVG format.


## Format of source

### HTML versus Markdown

We prefer Markdown for readability.

### Line wraps

Wrap lines at 80 characters—except [URLs](#line-breaks).


## Punctuation

### Commas

Use [serial (aka Oxford) commas](https://en.wikipedia.org/wiki/Serial_comma).

### Hyphens

Use hyphens only when necessary to prevent confusion. Examples include:
- A prefix ends in the same vowel that the word begins with: "re-entry".
- Compound modifiers: "You can find Calico easter eggs in read-only memory."


## Capitalization

### Proper nouns

Only capitalize proper nouns.

### Headings

Use [sentence case](https://www.snappysentences.com/sentence-case-v-title-case/)
for headings.


## Computer interfaces

### Code in headings

Do not include backticks in headings. If one or more words in the heading
is code, add descriptive text around it.

**Correct**:
```
# Setting the foo parameter
```

**Incorrect**:
```
# Setting `foo`
```

### Code samples

People often copy and paste the code that we provide. To prevent errors:

- Ensure that the code works.

- Enclose variable values in `<` and `>` characters. In the text,
  explicitly cite the variable by name and the need to replace it with an
  actual value before attempting to execute the code.

- Do not include `$` to indicate terminal entries. Instead, mention
  that the code is intended for entry in a terminal prompt in the
  text.

- Separate commands from responses.

Example:

> 1. Use the command below to apply a policy. After replacing
   `<your-policy>` with the name of the YAML file containing
   your policy, issue the command from a terminal.
>
>    ```
>    calicoctl apply -f <your-policy>
>    ```
>
> 1. It should return something like the following.
>
>    ```
>    Successfully applied 1 'policy' resource(s)
>    ```

### Docker images

Enclose the names of Docker images in backticks. Example: `calico/node`.

### URLs

#### URL versus URI

We prefer the term URL for reachable links over the more general URI. See
[RFC 3986](https://tools.ietf.org/html/rfc3986#section-1.1.3)
for more discussion on this topic.

#### Link text

Do not include URLs that a reader might want to visit in the text. Instead,
hyperlink a phrase that describes what the reader will see after following
the link.

**Correct**:
```
Refer to [Understanding the birthday paradox](https://betterexplained.com/articles/understanding-the-birthday-paradox/)
for more information.
```

**Incorrect**:
```
For more information about the birthday paradox,
[click here](https://betterexplained.com/articles/understanding-the-birthday-paradox/).
```
```
This link provides more information about the birthday paradox:
https://betterexplained.com/articles/understanding-the-birthday-paradox/.
```

#### External links

Append `{:target="_blank"}` to external links so that they open in
a new tab. Example:
```
Refer to [the kubeadm getting started guide](http://kubernetes.io/docs/getting-started-guides/kubeadm/){:target="_blank"}
for detailed instructions.
```

#### Line breaks

Do not insert line breaks inside a URL.


## Lists

### At least two items

A list should always contain at least two items. Do not use a list for only
one item.

### Parallel construction

Items in a list should have parallel construction.

**Correct**:
- Orange
- Apple
- Banana

**Incorrect**:
- Floppy disks are so great
- Juju beans
- Don't forget the mayo!

### Capitalize first word

Capitalize the first word of each list item, even if it's not a complete
sentence.

### Nested lists

Avoid exceeding two levels of nesting in a list.

### Introductory text

When a section contains only a list and the heading text explains its
contents clearly, you can omit introductory text. Example:

```
# Installing the Calico binary

1. [Download the binary](https://calico.org/downloads/latest-calico-binary)
   to your local drive.
1. Make the binary executable.
   `chmod +x calico-binary`
1. Add the binary to your `$PATH`.
   `sudo mv ./calico-binary /usr/local/bin/calico-binary`

# Next heading
```

When including introductory content to precede a list, we prefer
complete sentences. Example:

```
To add a node to your cluster, complete the following steps.

1. Open a terminal prompt.
...
```

### Punctuation

If the item is a complete sentence, include a period at the end. Otherwise,
omit trailing punctuation.

**Correct**
```
1. Ensure that you have an uninterrupted source of power.
1. Start the backup procedure.
1. Run some errands.
1. Check the status.
1. Have a snack.
1. Check the status.
```

**Incorrect**
```
1. Uninterrupted source of power.
1. Backup procedure.
1. Errands.
1. Status.
1. Snack.
1. Status.
```

**Incorrect**
```
Congratulations to the following winners of the Calico pop quiz:
- Joe,
- Bob, and
- Chris.
```


## Procedures

Use numbered lists to indicate a series of steps that should be performed
in sequence.

Avoid giving the reader more than one way to accomplish a task. Just
describe the best method.


## Numbers and dates

Spell out numbers zero through nine. Use numeric form for 10 and above.

Spell out dates.
- **Correct**: January 1, 1970
- **Incorrect**: Jan 1, 1970
- **Incorrect**: 1/1/1970


## Acronyms and file types

Treat file types as acronyms when used in text. Use all caps.
Examples:
- "Download the YAML file."
- "Calico checks the CONF file."

To pluralize an acronym, add a lowercase "s". Example: "Deploy the VMs in
a single click."


## Notes

While notes can help to call attention to important information, too
many can clutter the page and exhaust the reader.

For notes, use the following styles.

```
> **Tip**: not everyone needs to read this, but some might really
> appreciate (and even enjoy) the information.
{: .alert .alert-success}

> **Note**: this information deserves special attention.
{: .alert .alert-info}

> **Important**: this is required reading.
{: .alert .alert-danger}
```

Do not use `> **Warning**: ... {: .alert .alert-warning}`. This style
is reserved for the note that appears at the top of the page to let people
know they are viewing a version of the documentation other than the
current release.


## Storage, memory, and speed abbreviations

Don't put a space between the number and the abbreviation. Examples: 500Kbps,
1.3GHz.

Don't add an "s" after the abbreviation to form a plural.

- **Correct**: "The system requires 1.9GB of memory."
- **Incorrect**: "The system requires 1.9GBs of memory."

Repeat the abbreviation in a series. Example: "The device offers 2MB, 4MB,
or 6MB of storage."


## American conventions

### Spelling

Many countries spell various English words in different ways. Use the
American spelling. [Wikipedia](https://en.wikipedia.org/wiki/Wikipedia:Manual_of_Style/Spelling)
provides a table that shows some of the primary deviations. You can
also consult [Merriam-Webster](https://www.merriam-webster.com/).

### Numbers

Use a comma in whole numbers with four or more digits. Example: 1,200.

Use decimal points. Example, 2.5 pounds.


## Terminology

| Correct                  | Incorrect
| ------------------------ | ---------
| agent                    | slave
| allow-list               | whitelist
| API                      | api
| API server               | api server, apiserver
| deny-list                | blacklist
| DockerHub                | Dockerhub, dockerhub
| GitHub                   | Github, github
| email                    | e-mail, Email, E-mail
| etcd                     | Etcd, ETCD
| flannel                  | Flannel
| internet                 | Internet
| kubeadm                  | Kubeadmn
| Kubernetes API datastore | Kubernetes datastore, kdd datastore
| Mesos containerizer      | Unified containerizer, Universal containerizer
| `NetworkPolicy`          | NetworkPolicy
| network policy           | Network Policy, NetworkPolicy
| quickstart               | quick start, quick-start
| systemd                  | Systemd
| to                       | in order to
| tutorial or procedure    | worked example
| web interface            | GUI, UI
| web server               | webserver


## Commonly confused

### a | an

Use "a" when the following word starts with a consonant sound.
Examples: "a computer", " a user", "a hospital", "a UI".

Use "an" when the following word starts with a vowel sound.
Examples: "an MBA", "an hour", "an Ethernet card", "an opaque object".

### affect | effect

Use "affect" to indicate influence. Example: "I was so affected
by the performance, I began to cry."

Use "effect" to describe a causal relationship. Example: "They
brought him on to effect change."

### assure | ensure | insure

When you "assure" someone, you make them feel more confident and
remove their doubts. You can only assure human beings.

When you "ensure" something, you guarantee an outcome.
Example: "Ensure that you have removed all traces of your activity
before exiting the server."

**Tip**: In technical documentation, the word "ensure" is usually
the right choice.

The word "insure" should only be used in relation to actual insurers
and insurance policies.

### data

Use data as singular, not plural.

- **Correct**: "The data is..."
- **Incorrect**: "The data are..."

Use it as a mass noun, not a count noun.

- **Correct**: "less data"
- **Incorrect**: "fewer data"


### e.g. | i.e.

The abbreviation "e.g." refers to "exempli gratia" in Latin and means "for the sake of example."

The abbreviation "i.e." refers to "id est" in Latin and means "that is."

**Tips**:
- Always use a comma before and after both abbreviations.
- Do not use both abbreviations in the same sentence.
- If you start a list with "e.g.", do not include "etc." at the end.

### login | log in

Use "login" for the noun form. Use "log in" for verbs.

### its | it's

When forming a possessive of "it", omit the apostrophe. Example: "The
company never regained its reputation after the breach."

Include an apostrophe only for the contractions of "it is" and "it
has". Example: "It's very easy to install."

### setup | set up

Use "setup" for the noun or adjective form. Use "set up" for verbs.

### that | which

Use "that" to link an essential clause and "which" for inessential
clauses. If the meaning of the sentence would remain the same if you
deleted the clause, use "which".

**Examples**:
- "Give me the book that is on the table." There may be any number
  of books in the room, but the speaker wants the one on the table.

- "Give me the book, which is on the table." There is only one book
  in the room and it happens to be on the table.



