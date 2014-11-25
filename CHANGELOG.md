Version 0.2.0.0 (2014-11-25)
----------------------------

- API change: `getDefaultACL` now returns `IO (Maybe ACL)`, with `Nothing`
  indicating the absence of default ACL.
- Rewrite bindings to the Posix C API using monad transformers, and expose them
  in `System.Posix.ACL.C`.
- The `read` parser for `ACL` is more flexible in parsing valid ACLs, but does
  not parse ACLs with repeated user or group ids anymore.
- The `Show` instance of `ACL` now prints the short text form instead of the
  long text form.
- Enable Safe Haskell extension.
- Relicense under BSD3.
- Code and documentation improvements.

Version 0.1.0.0 (2013-03-15)
----------------------------

- Initial release.
