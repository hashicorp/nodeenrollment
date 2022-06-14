# Node Enrollment

This is a library that makes it easy to set up some complicated enrollment and
authentication/authorization flows for nodes, including in a proxied fashion.

It requires a minimal storage abstraction, but the functions provided can be
closures to tie the storage into e.g. transactions.

It supports transparent encryption of sensitive values if a [go-kms-wrapping
v2](https://github.com/hashicorp/go-kms-wrapping) wrapper is provided. For this
reason, use store and load methods on the types, rather than direct storage
functions, when using this library (unless you doing your own wrapping in your
storage implementation).

More information to come at a later date.
