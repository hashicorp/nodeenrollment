# [Very Much a WIP] Node Enrollment

**NOTE**: This is not necessarily the final name! I just needed something for
now.

This is a library to implement
[ICU-056](https://docs.google.com/document/d/1rlGhyv_g5Cuns66QoDfR2ZUlkkKTsAkJ5KCMSp8n9IE/edit)
in a way not tied to any particular product, so that the paradigms can be
generally useful.

It requires a minimal storage abstraction, but the functions provided can be
closures to tie the storage into e.g. transactions.

It supports transparent encryption of sensitive values if a [go-kms-wrapping
v2](https://github.com/hashicorp/go-kms-wrapping) wrapper is provided. For this
reason, use store and load methods on the types, rather than direct storage
functions, when using this library (unless you doing your own wrapping in your
storage implementation).

## Design

### Function Signatures

Most of the functions in this library do not operate as methods on a particular
type. The reason for this is the desire to support various storage abstractions,
including transaction-based storage. If the pattern were to load a value (such
as a `RootCertificate`) and then use a method on it to issue some credential,
it's possible that by the time the credential is issued we are actually using
the wrong root certificate because it's been rotated.

Because storage is an interface, it's possible for a caller of a function to
provide an implementation tied to a single transaction. Because this same
storage is passed to any other methods called and used to look up and store any
other required values in any of those methods, we can ensure that the caller is
in charge of if and when that transaction is committed.

Likewise, the library does not store or cache anything, with a specific caveat:
some packages (such as `nodeauth`) may provide something stateful, like a
listener. In these cases, those functions take in factory functions to produce
the required values. For instance, rather than singular root certificate ID, it
may take in a function that produces a root certificate ID, and that function
can be backed by any logic necessary.

### Packages

There are currently four packages:

#### Base Package

* The base package contains types and methods on several of those types, especially:
  * `RootCertificate`, which holds information about a root CA
  * `NodeInformation`, which is the information a server holds in its store that
    contains the information necessary to validate and perform
    encryption/decryption on messages from a node
  * `NodeCredentials`, which is the information a node holds storing its actual
    credentials that can be used for mutual TLS and encryption/decryption of
    messages to the server

There are also:

* A storage abstraction, split into two interfaces: `ServerStorage`
and `NodeStorage`, which contain the bits that must be implemented by either a
server or node.
    * ~> _Generally speaking, do not operate directly on storage; use the
      provided helper functions for the given types. This ensures that if an
      encryption wrapper is provided, it will be used!_
* EncryptMessage and DecryptMessage functions that can be used to encrypt or
  decrypt a proto message to a given server/node
    * These make use of functions for deriving shared encryption keys, which are
      also included

#### `storage` Package

This contains some implementations of the storage interfaces. Currently this is
only a file-backed implementation. Other users of the library will likely want
to write their own implementations.

#### `noderegistration` Package

This package provides functions to implement the various registration flows,
including both operator-led and node-led flows. See the README.md file there for
more information.

#### `nodeauth` Package

This package provides helpers to make implementation of the node authentication
workflows simple. See the README.md file there for more information.