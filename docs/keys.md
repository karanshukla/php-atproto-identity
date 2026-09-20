# Reading a published key

What `SigningKeys::atproto()` checks, why it hands back a list, and how a
compressed point becomes a PEM. The [README](../README.md#reading-a-published-key)
has the usage.

## What `SigningKeys::atproto()` checks

`SigningKeys::atproto()` is doing more than array access, and it is worth
saying what. A DID document is a list of keys and only some of them sign
repos: a `did:plc` document publishes a rotation key too, and that one signs
operations on the identity rather than anything you are verifying. So the
`#atproto` ones are picked out, and each is checked to belong to the document's
own subject. The obvious version of that check is
`str_ends_with($method['id'], '#atproto')`, which accepts a method whose id
reads `did:plc:somebodyelse#atproto` out of a document you resolved for
someone else entirely.

## Why a list

A list comes back rather than one key, because a document may publish more
than one and during a rotation the one that verifies a given signature may not
be the one listed first. Empty means the document publishes no ATProto signing
key at all, which a caller looping over the result rejects by doing nothing.

If you already have a key in hand, `DidKey::fromMultibase()` takes the
`publicKeyMultibase` string and `DidKey::fromDidKey()` takes the
`did:key:z...` form.

## From a compressed point to a PEM

ATProto publishes keys as a compressed point (an X coordinate and one bit of
Y), so a PEM means recovering Y by taking a modular square root in the curve's
field. RFC 5480 allows a `SubjectPublicKeyInfo` to carry a compressed point, so
the key is handed to OpenSSL exactly as published and comes back decompressed:
the square root happens in C and the on-curve check comes free. A build whose
OpenSSL declines falls back to the same arithmetic in PHP. Either way, a point
that is not on the curve is rejected, and rejected when the key is built: a
`VerificationKey` you are holding is one `pem()` will not throw on.
