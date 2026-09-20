# Security

## Reporting a vulnerability

Report it privately through GitHub, at
[Security > Report a vulnerability](https://github.com/karanshukla/php-atproto-identity/security/advisories/new).
That opens a draft advisory only you and the maintainer can see.

Please do not open a public issue for a vulnerability, and please do not put
one in a pull request description. Both are indexed within minutes.

Include what you have: the DID or input that triggers it, what you expected,
what happened instead, and the PHP version and extensions (`ext-gmp` in
particular, which changes which code path runs). A failing test against this
repository is the most useful thing you can send and the fastest thing to
act on.

Expect an acknowledgement within a week. If you do not get one, assume the
notification was missed rather than ignored, and open a public issue saying
only that you are waiting on a private report.

## What this package is responsible for

It turns a DID into a URL, fetches a document from it, and reads a signing
key out of that document. A DID is usually attacker-controlled, so the
following are in scope and a failure of any of them is a vulnerability:

| | |
|---|---|
| **URL construction** | A DID identifier that escapes the URL it is placed in: a different host, a different path, a query, a userinfo section. Percent-encoded or otherwise. |
| **Document attribution** | A document being accepted for a DID that is not the one it claims, or a key being attributed to a DID that did not publish it. |
| **Key decoding** | A point that is not on the curve being accepted, the parity bit being ignored, or a PEM being produced that does not match the published key. |
| **Resource use** | Input whose length or content costs time or memory out of proportion to it, on any supported build. |
| **Cache** | A cached document being served for the wrong DID, or a document being served after a check that should have refused it. |

## What it is not responsible for

Where a request *ends up* is the HTTP client's job, and the client is
supplied by the caller. This package bounds the URL it asks for. It cannot
bound DNS, redirects or egress, because it never sees them.

So these are documented limits rather than vulnerabilities:

- A public hostname that resolves to a private address, whether by DNS
  rebinding, a split-horizon resolver or a search domain.
- An allowed host answering with a 302 to somewhere else.
- A response that is slow rather than large, or a connection that never
  closes. Timeouts belong to the client.
- A host that is unreachable, or a PLC directory that is down. The resolver
  serves a stale document rather than failing, by design and within a bound
  you configure.

The README says how to hand this package a client that does bound those,
under *Resolving a DID you do not trust*. If you think one of these is
exploitable in a way that configuration cannot fix, report it anyway and say
why; the line above is a judgement, not a rule.

## Supported versions

The latest minor release, and only that. This package has no long-term
support branches. A fix ships as a new patch release and an advisory on the
repository.
