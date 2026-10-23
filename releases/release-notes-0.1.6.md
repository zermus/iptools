# iptools 0.1.6

iptools 0.1.6 is a maintenance release correcting the displayed footer version.
Release 0.1.5 incorrectly displayed v0.1.4 in its footer; this release corrects
it to v0.1.6.

## Highlights

- Corrects the stale footer version to v0.1.6.
- Adds a version-drift regression check comparing the rendered footer with the
  release builder's version.
- Retains test-tooling HTTP protections and CLI regression coverage for
  test-tooling access and MTR behavior.

## Installation

1. Download `ip-tools-0.1.6.tar.gz` or `ip-tools-0.1.6.zip` from the project
   release.
2. Back up the per-tool configuration values at the top of your installed PHP
   files.
3. Extract the archive into the web root, then reapply those configuration
   values.
4. Ensure `tmp/` exists and is writable by the web server when using MTR.

Release archives already exclude `tests/` and do not include or overwrite
runtime `logs/` and `tmp/` data. If deploying a source checkout instead, remove
`tests/` from the document root or deny all HTTP access to it at the web-server
level. Apache must honor the supplied `.htaccess` rules or use equivalent
virtual-host rules; Nginx and other servers need equivalent protection. See
`README.md` for configuration and verification guidance.

## Requirements

- PHP 7.3 or newer with the GMP extension for IPv6 tools.
- A web server that honors the supplied Apache rules, or equivalent rules for
  Nginx or other servers.
- The command-line utilities used by the enabled tools, including `timeout`.
- MTR installed for `mtr.php`; see `README.md` for optional sudo configuration.
